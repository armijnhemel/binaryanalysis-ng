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

'''
Parse and unpack DOS MZ files. Also extract data for one DOS extender
that uses COFF.

Test files: FreeDOS 1.2
'''

import os
from UnpackParser import UnpackParser, check_condition, OffsetInputFile
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import dos_mz
from . import coff


class DosMzClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MZ'),
        #(0, b'ZM')
    ]
    pretty_name = 'dos_mz'

    def parse(self):
        self.file_size = self.fileresult.filesize
        try:
            self.data = dos_mz.DosMz.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        if self.data.header.mz.last_page_extra_bytes == 0:
            self.end_of_data = self.data.header.mz.num_pages * 512
        else:
            self.end_of_data = (self.data.header.mz.num_pages - 1) * 512 + self.data.header.mz.last_page_extra_bytes
        check_condition(self.end_of_data <= self.fileresult.filesize,
                        "not enough data")

        self.extender = ''

        # it could be that there is extra COFF data after the
        # DOS MZ header and payload, example: many FreeDOS programs
        self.has_coff = False
        if self.end_of_data + self.offset != self.fileresult.filesize:
            if self.data.body.startswith(b'go32stub, v 2.0'):
                self.extender = 'DJGPP go32'
                self.has_coff = True

        if self.has_coff:
            self.coff_size = 0
            coff_offset = self.offset + self.end_of_data
            inf = OffsetInputFile(self.infile.infile, coff_offset)
            try:
                self.coff = coff.Coff.from_io(inf)
                self.coff_size = inf.tell()
                for section in self.coff.section_headers:
                    if section.ofs_section != 0:
                        check_condition(section.ofs_section + section.len_section <= self.fileresult.filesize - coff_offset,
                                        "section data outside of file")
                        self.coff_size = max(self.coff_size, section.ofs_section + section.len_section)
                    if section.ofs_relocation_table != 0:
                        check_condition(section.ofs_relocation_table <= self.fileresult.filesize - coff_offset,
                                        "section data outside of file")
                        self.coff_size = max(self.coff_size, section.ofs_relocation_table)
                    if section.ofs_line_number_table != 0:
                        check_condition(section.ofs_line_number_table <= self.fileresult.filesize - coff_offset,
                                        "section data outside of file")
                        self.coff_size = max(self.coff_size, section.ofs_line_number_table)

                if self.coff.symbol_table_and_string_table is not None:
                    symbol_size = self.coff.header.num_symbols * 18 + self.coff.symbol_table_and_string_table.len_string_table

                    # force read symbols
                    for s in self.coff.symbol_table_and_string_table.string_table.strings:
                        pass
                    self.coff_size = max(self.coff_size, self.coff.header.ofs_symbol_table + symbol_size)
            except (Exception, ValidationFailedError) as e:
                self.has_coff = False

    def calculate_unpacked_size(self):
        if not self.has_coff:
            self.unpacked_size = self.end_of_data
        else:
            self.unpacked_size = self.end_of_data + self.coff_size

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['dos_mz', 'executable']
        metadata = {}

        if self.has_coff:
            labels.append('coff')
            labels.append('DOS extender')
            if self.coff.symbol_table_and_string_table is not None:
                metadata['symbol_strings'] = self.coff.symbol_table_and_string_table.string_table.strings
            metadata['extender'] = self.extender

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
