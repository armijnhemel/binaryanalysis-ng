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

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import terminfo
from . import terminfo_extended


class TerminfoUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1a\x01')
    ]
    pretty_name = 'terminfo'

    def parse(self):
        '''Parse terminfo files in both extended format and regular format'''
        try:
            self.data = terminfo_extended.TerminfoExtended.from_io(self.infile)
        except (Exception, ValidationFailedError):
            self.infile.infile.seek(self.infile.offset)

            try:
                self.data = terminfo.Terminfo.from_io(self.infile)
            except (Exception, ValidationFailedError) as ex:
                raise UnpackParserException(ex.args) from ex

        # sanity checks for the names
        check_condition(len(self.data.names_section.names) > 0,
                        "no name found")
        check_condition(self.data.names_section.names.isprintable(),
                        "invalid names section")
        check_condition(re.match(r'[a-zA-Z0-9][a-zA-Z0-9.][^|]*', self.data.names_section.names) is not None,
                        "invalid terminal name")

        for string_offset in self.data.strings_section.string_offset:
            if string_offset in [0xffff, 0xfffe]:
                continue
            check_condition(string_offset <= self.data.len_string_table,
                            "invalid offset into string table")

    labels = ['resource', 'terminfo']
    metadata = {}
