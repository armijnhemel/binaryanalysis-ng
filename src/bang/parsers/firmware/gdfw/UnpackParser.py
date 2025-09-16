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

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import gdfw


class GdfwUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'GDFW')
    ]
    pretty_name = 'gdfw'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = gdfw.Gdfw.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        if self.data.header.len_hostfw != 0:
            file_path = pathlib.Path('hostfw')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.hostfw)
                yield unpacked_md

        if self.data.header.len_gcfw != 0:
            file_path = pathlib.Path('gcfw')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.hostfw)
                yield unpacked_md

    labels = ['gdfw', 'firmware']
    metadata = {}
