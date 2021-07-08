# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright 2018-2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import stat
import os
import pathlib
import sys
import traceback
from operator import itemgetter

from FileResult import FileResult

class AnalysisJobError(Exception):
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, scanjob, e):
        super().__init__(self, scanjob, e)
        self.scanjob = scanjob
        self.e = e

    def __str__(self):
        exc = traceback.format_exception(type(self.e), self.e, self.e.__traceback__, chain=False)
        if self.scanjob is not None:
            return """Exception for scanjob:
file:
    %s
labels:
    %s
""" % (str(self.scanjob.fileresult.filename), ",".join(self.scanjob.fileresult.labels)) + "".join(exc)
        else:
            return "Exception (no scanjob):\n\n" + "".join(exc)


class AnalysisJob:
    """Performs analysis related checks and stores the
    results in the given FileResult object."""
    def __init__(self, fileresult):
        self.fileresult = fileresult
        self.type = None

    def set_scanenvironment(self, scanenvironment):
        self.scanenvironment = scanenvironment

    def initialize(self):
        self.abs_filename = self.scanenvironment.unpack_path(self.fileresult.filename)
        self._stat_file()

    def _stat_file(self):
        try:
            self.stat = os.stat(self.abs_filename)
        except FileNotFoundError as e:
            #raise
            self.stat = None
        except:
            self.stat = None

    def _is_symlink(self):
        r = self.abs_filename.is_symlink()
        if r: self.type = 'symbolic link'
        return r

    def _is_socket(self):
        r = stat.S_ISSOCK(self.stat.st_mode)
        if r: self.type = 'socket'
        return r

    def _is_fifo(self):
        r = stat.S_ISFIFO(self.stat.st_mode)
        if r: self.type = 'fifo'
        return r

    def _is_block_device(self):
        r = stat.S_ISBLK(self.stat.st_mode)
        if r: self.type = 'block device'
        return r

    def _is_character_device(self):
        r = stat.S_ISCHR(self.stat.st_mode)
        if r: self.type = 'character device'
        return r

    def _is_directory(self):
        r = self.abs_filename.is_dir()
        if r: self.type = 'directory'
        return r

    def _is_empty(self):
        r = self.stat.st_size == 0
        if r: self.type = 'empty'
        return r

    def not_scannable(self):
        return self._is_symlink() or \
                self._is_socket() or \
                self._is_fifo() or \
                self._is_block_device() or \
                self._is_character_device() or \
                self._is_directory() or \
                self._is_empty()

    def check_unscannable_file(self):
        if self.not_scannable():
            self.fileresult.labels.add(self.type)
            if self.type == 'empty':
                self.fileresult.set_filesize(0)
                for hash_algorithm, hash_value in emptyhashresults.items():
                    self.fileresult.set_hashresult(hash_algorithm, hash_value)
            return True
        self.fileresult.set_filesize(self.stat.st_size)
        return False



# Process a single file.
# This method has the following parameters:
#
# * scanenvironment :: an AnalysisEnvironment object, describing
#   the environment for the scan
#
# The scan queue contains AnalysisJob objects
#
# For every file a set of labels describing the file (such as 'binary' or
# 'graphics') has been stored. These labels can be used to feed extra
# information to the analysis process, such as preventing scans from
# running.
def processfile(scanenvironment):

    scanfilequeue = scanenvironment.scanfilequeue
    processlock = scanenvironment.processlock
    checksumdict = scanenvironment.checksumdict

    while True:
        try:
            scanjob = scanfilequeue.get(timeout=86400)
            if not scanjob: continue
            scanjob.set_scanenvironment(scanenvironment)
            scanjob.initialize()
            fileresult = scanjob.fileresult

            unscannable = scanjob.check_unscannable_file()
            if unscannable:
                scanfilequeue.task_done()
                continue

            unpacker = UnpackManager(scanenvironment.unpackdirectory)

            scanjob.check_for_padding_file(unpacker)
            scanjob.check_for_unpacked_file(unpacker)
            scanjob.check_mime_types()

            if unpacker.needs_unpacking():
                scanjob.check_for_valid_extension(unpacker)

            if unpacker.needs_unpacking():
                scanjob.check_for_signatures(unpacker)

            scanjob.do_content_computations()

            if unpacker.needs_unpacking():
                scanjob.check_entire_file(unpacker)

            processlock.acquire()

            if scanjob.fileresult.get_hash() in checksumdict:
                scanjob.fileresult.set_duplicate(True)
            else:
                scanjob.fileresult.set_duplicate(False)
                checksumdict[scanjob.fileresult.get_hash()] = scanjob.fileresult.filename
            processlock.release()

            if not scanjob.fileresult.is_duplicate():
                for rclass in scanenvironment.reporters:
                    r = rclass(scanenvironment)
                    r.report(scanjob.fileresult)

            # scanjob.fileresult.set_filesize(scanjob.filesize)

            scanfilequeue.task_done()
        except Exception as e:
            tb = sys.exc_info()[2]
            if scanjob:
                raise AnalysisJobError(scanjob, e)
                # raise AnalysisJobError(scanjob, e).with_traceback(tb)
            else:
                raise AnalysisJobError(None, e).with_traceback(tb)
