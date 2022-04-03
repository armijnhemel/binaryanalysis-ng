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

# Parser for TrueType and OpenType fonts

import math
import os

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ttf as ttf

# https://docs.microsoft.com/en-us/typography/opentype/spec/otff
# (section 'Font Tables')
# the following tables are required for an OpenType font:
REQUIRED_OPENTYPE = set(['cmap', 'head', 'hhea', 'hmtx',
                         'maxp', 'name', 'OS/2', 'post'])

# https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html
# (table 2)
# the following tables are required for a TrueType font:
REQUIRED_TRUETYPE = set(['cmap', 'glyf', 'head', 'hhea', 'hmtx',
                         'loca', 'maxp', 'name', 'post'])


class TruetypeFontUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00\x01\x00\x00'),
        (0, b'OTTO')
    ]
    pretty_name = 'truetype'

    def parse(self):
        self.unpacked_size = self.infile.tell()
        try:
            self.data = ttf.Ttf.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        try:
            log_tables = int(math.log2(self.data.offset_table.num_tables))
        except ValueError as e:
            raise UnpackParserException(e.args)

        check_condition(pow(2, log_tables) * 16 == self.data.offset_table.search_range,
                        "number of tables does not correspond to search range")

        check_condition(log_tables == self.data.offset_table.entry_selector,
                        "number of tables does not correspond to entrySelector")

        check_condition(self.data.offset_table.range_shift == self.data.offset_table.num_tables * 16 - self.data.offset_table.search_range,
                        "invalid range shift")

        table_names = set()
        table_offsets = {}

        try:
            for dir_table_entry in self.data.directory_table:
                # each table can only appear in a font once
                check_condition(dir_table_entry.tag not in table_names,
                                "duplicate table")
                table_names.add(dir_table_entry.tag)
                table_offsets[dir_table_entry.tag] = dir_table_entry.offset

                # read data because Kaitai Struct evaluates instances lazily
                value = dir_table_entry.value

                # the length of the table does not include any padding bytes
                # This can be relevant for padding at the end of the file.
                if dir_table_entry.length % 4 != 0:
                    dir_length = dir_table_entry.length + (4 - dir_table_entry.length % 4)
                else:
                    dir_length = dir_table_entry.length

                self.unpacked_size = max(self.unpacked_size, dir_table_entry.offset + dir_length)

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
                                    "invalid checksum for table %s" % dir_table_entry.tag)
                else:
                    # the head table checksum is different and uses a
                    # checksum adjustment, which is documented here:
                    # https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6head.html
                    # Skip 8 bytes from the start of the table and then read
                    # the checksum adjustument
                    checksum_adjustment = int.from_bytes(dir_table_entry.raw_value[8:12], byteorder='big')

        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.offset + self.unpacked_size <= self.fileresult.filesize,
                        "not enough data")

        # then compute the font checksum
        font_checksum = 0
        self.infile.seek(0)
        for i in range(0, self.unpacked_size, 4):
            if i == table_offsets['head'] + 8:
                self.infile.seek(4, os.SEEK_CUR)
                continue
            checkbytes = self.infile.read(4)
            font_checksum += int.from_bytes(checkbytes, byteorder='big')
        # TODO: padding at the end of the last table, if any

        # only grab the lowest 32 bits (4294967295 = (2^32)-1)
        font_checksum = font_checksum & 4294967295

        if checksum_adjustment != 0xB1B0AFBA - font_checksum:
            # some fonts, such as the the Ubuntu ones use a different
            # value for checksumadjustment
            if checksum_adjustment != 0x1B1B0AFBA - font_checksum:
                raise UnpackParserException("checksum adjustment does not match computed value")

        self.infile.seek(0)
        magic = self.infile.read(4)
        if magic == b'OTTO':
            self.fonttype = 'opentype'
            check_condition(table_names.intersection(REQUIRED_OPENTYPE) == REQUIRED_OPENTYPE,
                            "not all required opentype tables present")
        else:
            # first check if all the required tables are there.
            # It could be that the font is actually a "sfnt-housed font" and
            # then not all the tables need to be there.
            if table_names.intersection(REQUIRED_TRUETYPE) != REQUIRED_TRUETYPE:
                self.fonttype = 'sfnt'
            else:
                self.fonttype = 'truetype'

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [self.fonttype, 'font']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
