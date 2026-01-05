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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import hp_bdl


class HpBdlUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ibdl')
    ]
    pretty_name = 'hp_bdl'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = hp_bdl.HpBdl.from_io(self.infile)
            self.unpacked_size = max(self.unpacked_size, self.data.header.ofs_toc)

            # ugly hack to read all the data and find the size
            # of the unpacked data
            for entry in self.data.file_offset_table.entries:
                self.unpacked_size = max(self.unpacked_size, entry.ofs_entry + entry.len_entry)

                for e in entry.entry.entries:
                    self.unpacked_size = max(self.unpacked_size, entry.ofs_entry + e.ofs_data + e.len_data)
                    check_condition(len(e.data) == e.len_data, "not enough data")
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        for entry in self.data.file_offset_table.entries:
            for e in entry.entry.entries:
                if e.name == '':
                    continue
                file_path = pathlib.Path(e.name)

                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(e.data)
                    yield unpacked_md

    labels = ['hp bdl', 'firmware']
    metadata = {}
