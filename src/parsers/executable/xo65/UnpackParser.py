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

import os

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import xo65


class Xo65UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x55\x7a\x6e\x61')
    ]
    pretty_name = 'xo65'

    def parse(self):
        try:
            self.data = xo65.Xo65.from_io(self.infile)
            self.unpacked_size = self.infile.tell()

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_options + self.data.object_header.len_options)
            check_condition(len(self.data.object_header.options) == self.data.object_header.len_options,
                            "not enough data for options")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_file_table + self.data.object_header.len_file_table)
            check_condition(len(self.data.object_header.file_table) == self.data.object_header.len_file_table,
                            "not enough data for file table")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_segment_table + self.data.object_header.len_segment_table)
            check_condition(len(self.data.object_header.segment_table) == self.data.object_header.len_segment_table,
                            "not enough data for segment table")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_import_list + self.data.object_header.len_import_list)
            check_condition(len(self.data.object_header.import_list) == self.data.object_header.len_import_list,
                            "not enough data for import list")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_export_list + self.data.object_header.len_export_list)
            check_condition(len(self.data.object_header.export_list) == self.data.object_header.len_export_list,
                            "not enough data for export list")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_debug_symbols_list + self.data.object_header.len_debug_symbols_list)
            check_condition(len(self.data.object_header.debug_symbols_list) == self.data.object_header.len_debug_symbols_list,
                            "not enough data for debug symbols")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_line_infos + self.data.object_header.len_line_infos)
            check_condition(len(self.data.object_header.line_infos) == self.data.object_header.len_line_infos,
                            "not enough data for line infos")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_string_pool + self.data.object_header.len_string_pool)
            for s in self.data.object_header.string_pool.entries:
                pass

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_assertion_table + self.data.object_header.len_assertion_table)
            check_condition(len(self.data.object_header.assertion_table) == self.data.object_header.len_assertion_table,
                            "not enough data for assertion table")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_scope_table + self.data.object_header.len_scope_table)
            check_condition(len(self.data.object_header.scope_table) == self.data.object_header.len_scope_table,
                            "not enough data for scope table")

            self.unpacked_size = max(self.unpacked_size, self.data.object_header.ofs_span_table + self.data.object_header.len_span_table)
            check_condition(len(self.data.object_header.span_table) == self.data.object_header.len_span_table,
                            "not enough data for span table")

        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def extract_metadata_and_labels(self):
        '''Extract metadata from the xo65 file and set labels'''
        labels = ['xo65', 'object file']
        metadata = {}

        return (labels, metadata)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        (labels, metadata) = self.extract_metadata_and_labels()
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
