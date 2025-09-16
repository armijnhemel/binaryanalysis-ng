# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

import os
import pathlib
import shutil
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args) from e

        # check if the file starts at offset 0 as unzck expects that
        # zchunk data starts at offset 0.
        # If not this is not the case, carve the file first.
        self.havetmpfile = False
        if not self.offset == 0:
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            self.havetmpfile = True
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.infile.tell())
            os.fdopen(self.temporary_file[0]).close()

        # test unpack to /dev/null to see if the data is valid
        if self.havetmpfile:
            p = subprocess.Popen(['unzck', '-c', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        else:
            # ??
            p = subprocess.Popen(['unzck', '-c', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if p.returncode != 0 and self.havetmpfile:
            os.unlink(self.temporary_file[1])
        check_condition(p.returncode == 0, "zck unpacking error")

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.zck':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_zchunk")
        else:
            file_path = pathlib.Path("unpacked_from_zchunk")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # TODO: find a way to deal with offsets in input file
            if self.havetmpfile:
                p = subprocess.Popen(['unzck', '-c', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)
            else:
                p = subprocess.Popen(['unzck', '-c', meta_directory.file_path], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()

            if self.havetmpfile:
                os.unlink(self.temporary_file[1])

            yield unpacked_md

    labels = ['zchunk', 'compressed']
    metadata = {}
