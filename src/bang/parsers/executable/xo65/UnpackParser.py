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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args) from e

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['xo65', 'object file']
    metadata = {}
