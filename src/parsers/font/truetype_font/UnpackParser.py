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

import math
import os

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ttf as ttf

from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_truetype_font


#class TruetypeFontUnpackParser(WrappedUnpackParser):
class TruetypeFontUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00\x01\x00\x00'),
        #(0, b'OTTO')
    ]
    pretty_name = 'truetype'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_truetype_font(fileresult, scan_environment, offset, unpack_dir)

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

        try:
            for dir_table_entry in self.data.directory_table:
                # each table can only appear in a font once
                check_condition(dir_table_entry.tag not in table_names,
                                "duplicate table")
                table_names.add(dir_table_entry.tag)

                # read data because Kaitai Struct evaluates instances lazily
                value = dir_table_entry.value

                self.unpacked_size = max(self.unpacked_size, dir_table_entry.offset + dir_table_entry.length)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.offset + self.unpacked_size <= self.fileresult.filesize,
                        "not enough data")


    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ttf', 'font']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
