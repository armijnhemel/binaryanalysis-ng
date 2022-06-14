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


import os
import pathlib
import shutil
import subprocess
import tempfile

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import lz4_legacy

class Lz4legacyUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x02\x21\x4c\x18')
    ]
    pretty_name = 'lz4_legacy'

    def parse(self):
        if shutil.which('lz4c') is None:
            raise UnpackParserException("lz4c not installed")
        try:
            self.data = lz4_legacy.Lz4Legacy.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = 4
        for block in self.data.blocks:
            if not block.is_magic:
                self.unpacked_size += 4 + block.len_data

    # no need to carve from the file
    def carve(self):
        pass

    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        # unpack the data using lz4c. Currently the python-lz4 package
        # does not support the legacy format, see
        # https://github.com/python-lz4/python-lz4/issues/169
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.lz4':
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_lz4legacy")
        else:
            file_path = pathlib.Path("unpacked_from_lz4legacy")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)

        # check if the file starts at offset 0 and if the file length
        # equals the entire file. If not, carve the file first, as multiple
        # streams can be concatenated and lz4c will concatenate result
        havetmpfile = False
        if not (self.offset == 0 and self.fileresult.filesize == self.unpacked_size):
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            havetmpfile = True
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

        if havetmpfile:
            p = subprocess.Popen(['lz4c', '-d', temporary_file[1], outfile_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['lz4c', '-d', self.fileresult.filename, outfile_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if havetmpfile:
            os.unlink(temporary_file[1])

        if p.returncode != 0:
            return unpacked_files

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
        unpacked_files.append(fr)

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['compressed', 'lz4']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
