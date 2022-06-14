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
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# QCOW2 is a file format used by QEMU. It can be inspected and converted
# using the qemu-img tool, but tool isn't completely accurate: the
# "actual size" that is reported often isn't accurate (too large), making
# carving difficult. For most practical purposes it is probably good
# enough to look at the entire file.

import json
import os
import pathlib
import shutil
import subprocess
import tempfile

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import qcow2

class Qcow2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QFI\xfb')
    ]
    pretty_name = 'qcow2'

    def parse(self):
        check_condition(shutil.which('qemu-img') is not None,
                        "qemu-img program not found")
        check_condition(self.offset == 0, "carving not supported")
        try:
            self.data = qcow2.Qcow2.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # run qemu-img to see if the whole file is the qcow2 file
        # Carving unfortunately doesn't seem to work well.
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', self.fileresult.filename],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()
        check_condition(p.returncode == 0, "not a valid qcow2 file or cannot unpack")

        try:
            vmdkjson = json.loads(standardout)
        except:
            raise UnpackParserException("no valid JSON output from qemu-img")

        # convert the file to a temporary file
        temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
        os.fdopen(temporary_file[0]).close()
        p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw',self.fileresult.filename, temporary_file[1]],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()
        os.unlink(temporary_file[1])
        check_condition(p.returncode == 0, "not a valid qcow2 file or cannot unpack")
        self.unpacked_size = min(vmdkjson['actual-size'], self.fileresult.filesize)

    def unpack(self):
        unpacked_files = []

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() in ['.qcow2', '.qcow', '.qcow2c', '.img']
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_qcow2")
        else:
            file_path = pathlib.Path("unpacked_from_qcow2")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)

        p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw',self.fileresult.filename, outfile_full],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()

        fr = FileResult(self.fileresult, outfile_rel, set([]))
        unpacked_files.append(fr)
        return unpacked_files


    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['qemu', 'qcow2', 'filesystem']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
