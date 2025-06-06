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
from . import romfs_ambarella


class RomfsAmbarellaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (4, b'\x8a\x32\xfc\x66')
    ]
    pretty_name = 'romfs_ambarella'

    def parse(self):
        try:
            self.data = romfs_ambarella.RomfsAmbarella.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        self.unpacked_size = 0
        for entry in self.data.file_headers:
            self.unpacked_size = max(self.unpacked_size, entry.ofs_data + entry.len_data)
        check_condition(self.infile.size >= self.unpacked_size, "not enough data")

    def unpack(self, meta_directory):
        for entry in self.data.file_headers:
            file_path = pathlib.Path(entry.name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.data)
                yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['ambarella', 'filesystem']
    metadata = {}
