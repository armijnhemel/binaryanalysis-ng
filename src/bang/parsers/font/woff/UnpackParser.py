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

import zlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import woff


class WoffUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'wOFF')
    ]
    pretty_name = 'woff'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = woff.Woff.from_io(self.infile)

            # check all the tables, some sanity checks and read the data
            # to work around lazy evaluation in Kaitai
            for table in self.data.woff.table_directories:
                check_condition(table.len_data <= table.len_uncompressed_data,
                                "invalid table length")
                if table.len_data != table.len_uncompressed_data:
                    data = zlib.decompress(table.data.data)
                    check_condition(len(data) == table.len_uncompressed_data,
                                    "invalid zlib compressed data")
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    labels = ['woff', 'font', 'resource']
    metadata = {}
