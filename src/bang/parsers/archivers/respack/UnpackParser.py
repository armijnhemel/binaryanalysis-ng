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
# Copyright - Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import json
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import respack


class ResPackUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'RS')
    ]
    pretty_name = 'respack'

    def parse(self):
        try:
            self.data = respack.Respack.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        try:
            self.file_metadata = json.loads(self.data.json)
        except Exception as e:
            raise UnpackParserException(e.args) from e

        check_condition(isinstance(self.file_metadata, dict), "invalid JSON result type")

        # offsets for files are relative to the end of the JSON data
        self.end_of_json_offset = self.infile.tell()
        self.unpacked_size = self.infile.tell()

        check_condition('files' in self.file_metadata, "invalid ResPack JSON")

        for f in self.file_metadata['files']:
            check_condition('n' in f, "invalid ResPack JSON")
            check_condition(f['n'] != '', "invalid file name in ResPack JSON")
            check_condition('p' in f, "invalid ResPack JSON")
            check_condition('l' in f, "invalid ResPack JSON")

            check_condition(self.end_of_json_offset + f['p'] + f['l'] <= self.infile.size,
                            "data cannot be outside of file")
            self.unpacked_size = max(self.unpacked_size, self.end_of_json_offset + f['p'] + f['l'])

        # check the md5
        self.infile.seek(46)
        md5 = hashlib.md5(self.infile.read(self.unpacked_size - 46))
        check_condition(md5.hexdigest() == self.data.header.md5, "invalid MD5 checksum")

    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        for f in self.file_metadata['files']:
            file_path = pathlib.Path(f['n'])

            self.infile.seek(self.end_of_json_offset + f['p'])
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.infile.read(f['l']))
                yield unpacked_md

    labels = ['resource', 'respack']
    metadata = {}
