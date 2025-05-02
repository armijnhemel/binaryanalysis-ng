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

import pathlib
import zlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import trx


class TrxUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'HDR0')
    ]
    pretty_name = 'trx'

    def parse(self):
        try:
            self.data = trx.Trx.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        computed_crc = ~zlib.crc32(self.data.raw_data) & 0xffffffff
        check_condition(self.data.preheader.crc32 == computed_crc,
                        "invalid CRC32")

    def unpack(self, meta_directory):
        if self.data.header_and_data.header.ofs_partition0 != 0:
            file_path = pathlib.Path("partition0")
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.header_and_data.header.partition0)
                yield unpacked_md
        if self.data.header_and_data.header.ofs_partition1 != 0:
            file_path = pathlib.Path("partition1")
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.header_and_data.header.partition1)
                yield unpacked_md
        if self.data.header_and_data.header.ofs_partition2 != 0:
            file_path = pathlib.Path("partition2")
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.header_and_data.header.partition2)
                yield unpacked_md

        if self.data.header_and_data.header.ofs_partition3 != 0:
            file_path = pathlib.Path("partition3")
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.header_and_data.header.partition3)
                yield unpacked_md

    labels = ['trx', 'firmware', 'broadcom']
    metadata = {}
