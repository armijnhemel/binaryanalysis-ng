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
Parse and unpack Preferred Executable Format (PEF) files,
as used on classic MacOS.
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import pef


class PefClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'Joy!peff'),
    ]
    pretty_name = 'pef'

    def parse(self):
        try:
            self.data = pef.Pef.from_io(self.infile)

            self.unpacked_size = self.infile.tell()

            # force read part of the sections
            for s in self.data.section_headers:
                self.unpacked_size = max(self.unpacked_size, s.ofs_container + s.len_packed)
                if s.section_kind != pef.Pef.Section.loader:
                    check_condition(len(s.section) == s.len_packed,
                                    "not enough data")
                else:
                    symbols = s.section.header.symbols
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def calculate_unpacked_size(self):
        pass

    labels = ['pef', 'executable', 'macos']

    # TODO: filter/store symbols
    metadata = {}
