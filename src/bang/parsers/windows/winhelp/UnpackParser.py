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

'''
Parse and unpack Windows Help (.hlp) files.
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import winhelp


class WinhelpClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3f\x5f\x03\x00')
    ]
    pretty_name = 'winhelp'

    def parse(self):
        try:
            self.data = winhelp.Winhelp.from_io(self.infile)

            # force read some data
            for i in self.data.internal_directory.contents.leaf_page.entries:
                check_condition(i.ofs_fileheader + i.file.header.len_reserved_space <= self.data.len_file,
                                "leaf entry cannot be outside of file")
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.len_file

    labels = ['winhelp', 'resource']
    metadata = {}
