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
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import os

class ScanEnvironment:
    tlshlabelsignore = set([
        'compressed', 'graphics', 'audio', 'archive',
        'filesystem', 'srec', 'ihex', 'padding',
        'database'])

    def __init__(self, maxbytes, readsize, createbytecounter, createjson,
                 tlshmaximum, synthesizedminimum, logging, paddingname,
                 unpackdirectory, temporarydirectory, resultsdirectory,
                 scanfilequeue, resultqueue,
                 processlock, checksumdict,
                ):
        """unpackdirectory: a Path object
           temporarydirectory: a Path object
           scanfilequeue: a Queue where files to scan will be fetched from
           resultqueue: a Queue where results will be written to
           processlock: a Lock object that guards access to shared objects
           checksumdict: a shared dictionary to store hashes of files to
                         prevent scans of duplicate files.
        """
        # TODO: init from options object
        self.maxbytes = maxbytes
        self.readsize = readsize
        self.createbytecounter = createbytecounter
        self.createjson = createjson
        self.tlshmaximum = tlshmaximum
        self.synthesizedminimum = synthesizedminimum
        self.logging = logging
        self.paddingname = paddingname
        self.unpackdirectory = unpackdirectory
        self.temporarydirectory = temporarydirectory
        self.resultsdirectory = resultsdirectory
        self.lenunpackdirectory = len(str(unpackdirectory))+1
        self.scanfilequeue = scanfilequeue
        self.resultqueue = resultqueue
        self.processlock = processlock
        self.checksumdict = checksumdict

    def get_readsize(self):
        return self.readsize

    def get_createbytecounter(self):
        return self.createbytecounter

    def get_createjson(self):
        return self.createjson

    def get_tlshmaximum(self):
        return self.tlshmaximum

    def use_tlsh(self, filesize, labels):
        """check whether tlsh is useful here, based on file size and labels."""
        return (256 <= filesize <= self.tlshmaximum) and self.tlshlabelsignore.isdisjoint(labels)

    def get_synthesizedminimum(self):
        return self.synthesizedminimum

    def get_paddingname(self):
        return self.paddingname

    def get_maxbytes(self):
        return self.maxbytes

    def get_relative_path(self, fn):
        """Gets the path relative to the unpackdirectory."""
        return fn[self.lenunpackdirectory:]

    def unpack_path(self, fn):
        """Returns a path object containing the absolute path of the file in
        the unpack directory root.
        If fn is an absolute path, then fn will be returned.
        """
        return self.unpackdirectory / fn

    def rel_unpack_path(self, fn):
        # TODO: check if fn starts with unpackdirectory to catch path traversal
        # in that case, return absolute path? but what about:
        # >>> os.path.relpath('xa/b/c/d/e',root)
        # '../../../home/tim/binaryanalysis-ng/src/xa/b/c/d/e'
        return os.path.relpath(fn, self.unpackdirectory)

    def tmp_path(self, fn):
        return os.path.join(self.temporarydirectory, fn)

    def rel_tmp_path(self, fn):
        return os.path.relpath(fn, self.temporarydirectory)
