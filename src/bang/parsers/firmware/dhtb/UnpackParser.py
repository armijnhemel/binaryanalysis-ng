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

import binascii
import hashlib
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import dhtb


class DhtbUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DHTB\x01\x00\x00\x00')
    ]
    pretty_name = 'dhtb'

    def parse(self):
        try:
            self.data = dhtb.Dhtb.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e
        sha256 = hashlib.sha256(self.data.payload)
        check_condition(sha256.hexdigest() == binascii.hexlify(self.data.header.sha256).decode(),
                        'invalid hash')

    def unpack(self, meta_directory):
        unpacked_files = []

        file_path = pathlib.Path('payload')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.payload)
            yield unpacked_md

    labels = ['dhtb', 'android']
    metadata = {}
