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

import hashlib
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ah00


class Aih0UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'AH00')
    ]
    pretty_name = 'ah00'

    def parse(self):
        try:
            self.data = ah00.Ah00.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        data_checksum = hashlib.md5(self.data.data)
        check_condition(self.data.md5 == data_checksum.digest(), "MD5 mismatch")

    def unpack(self, meta_directory):
        file_path = pathlib.Path('data')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.data)
            yield unpacked_md

    labels = ['aah0', 'firmware']
    metadata = {}
