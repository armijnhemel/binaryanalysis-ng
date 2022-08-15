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
from . import zchunk


class ZchunkUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\0ZCK1')
    ]
    pretty_name = 'zchunk'

    def parse(self):
        if shutil.which('unzck') is None:
            raise UnpackParserException("unzck not installed")
        try:
            self.data = zchunk.Zchunk.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        out_labels = []

        # check if the file starts at offset 0 as unzck expects that
        # zchunk data starts at offset 0.
        # If not this is not the case, carve the file first.
        havetmpfile = False
        if not (self.offset == 0 and self.fileresult.filesize == self.infile.tell()):
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            havetmpfile = True
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.infile.tell())
            os.fdopen(temporary_file[0]).close()

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.zck':
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_zchunk")
        else:
            file_path = pathlib.Path("unpacked_from_zchunk")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)

        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        if havetmpfile:
            p = subprocess.Popen(['unzck', '-c', temporary_file[1]], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['unzck', '-c', self.fileresult.filename], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if havetmpfile:
            os.unlink(temporary_file[1])

        outfile.close()

        check_condition(p.returncode == 0, "zck unpacking error")

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['zchunk', 'compressed']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
