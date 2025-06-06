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

import math

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import otff

REQUIRED_TABLES = set(['cmap', 'head', 'hhea', 'hmtx',
                       'maxp', 'name', 'OS/2', 'post'])


class OpentypeFontCollectionUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ttcf')
    ]
    pretty_name = 'ttc'

    def parse(self):
        try:
            self.data = otff.Otff.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        self.unpacked_size = self.infile.tell()

        offset_to_checksum = {}

        for font in self.data.fonts:
            try:
                log_tables = int(math.log2(font.offset_table.num_tables))
            except ValueError as e:
                raise UnpackParserException(e.args) from e
            check_condition(pow(2, log_tables) * 16 == font.offset_table.search_range,
                            "number of tables does not correspond to search range")

            check_condition(log_tables == font.offset_table.entry_selector,
                            "number of tables does not correspond to entrySelector")

            check_condition(font.offset_table.range_shift == font.offset_table.num_tables * 16 - font.offset_table.search_range,
                            "invalid range shift")

            table_names = set()

            try:
                for dir_table_entry in font.offset_table.directory_table:
                    # each table can only appear in a font once
                    check_condition(dir_table_entry.tag not in table_names,
                                    "duplicate table")
                    table_names.add(dir_table_entry.tag)

                    # read data because Kaitai Struct evaluates instances lazily
                    value = dir_table_entry.raw_value

                    # the length of the table does not include any padding bytes
                    # This can be relevant for padding at the end of the file.
                    if dir_table_entry.length % 4 != 0:
                        dir_length = dir_table_entry.length + (4 - dir_table_entry.length % 4)
                    else:
                        dir_length = dir_table_entry.length

                    self.unpacked_size = max(self.unpacked_size, dir_table_entry.offset + dir_length)

                    if dir_table_entry.offset in offset_to_checksum:
                        computed_checksum = offset_to_checksum[dir_table_entry.offset]
                    else:
                        # compute checksum
                        computed_checksum = 0
                        checksum_bytes = dir_table_entry.raw_value
                        if len(dir_table_entry.raw_value) % 4 != 0:
                            padding_needed = 4 - len(dir_table_entry.raw_value) % 4
                            checksum_bytes += padding_needed * b'\x00'

                        for j in range(0, len(checksum_bytes), 4):
                            computed_checksum += int.from_bytes(checksum_bytes[j:j+4], byteorder='big')

                    # only grab the lowest 32 bits (4294967295 = (2^32)-1)
                    computed_checksum = computed_checksum & 4294967295
                    if dir_table_entry.tag != 'head':
                        check_condition(dir_table_entry.checksum == computed_checksum,
                                        f"invalid checksum for table {dir_table_entry.tag}")
                        offset_to_checksum[dir_table_entry.offset] = computed_checksum
                    else:
                        # the head table checksum is different and uses a
                        # checksum adjustment, which is documented here:
                        # https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6head.html
                        # Skip 8 bytes from the start of the table and then read
                        # the checksum adjustument
                        checksum_adjustment = int.from_bytes(dir_table_entry.raw_value[8:12], byteorder='big')

            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args) from e

            check_condition(table_names.intersection(REQUIRED_TABLES) == REQUIRED_TABLES,
                            "not all required tables present")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['font', 'open type font collection', 'resource']
    metadata = {}

    # TODO: extract font name
