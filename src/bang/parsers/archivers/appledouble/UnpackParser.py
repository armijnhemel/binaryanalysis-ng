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
Unpacker for AppleDouble encoded files. The format is described in
appendices A & B of:

https://tools.ietf.org/html/rfc1740

test files: any ZIP file unpacked on MacOS X which
has a directory called "__MACOSX"
Files starting with ._ are likely AppleDouble encoded
'''

import os
from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import apple_single_double


class AppledoubleUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00\x05\x16\x07')
    ]
    pretty_name = 'appledouble'

    def parse(self):
        try:
            self.data = apple_single_double.AppleSingleDouble.from_io(self.infile)
            # this is a bit of an ugly hack as the Kaitai parser is
            # not entirely complete. Use this to detect if the file
            # has been truncated.
            for i in self.data.entries:
                a = type(i.body)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.num_entries > 1, "no apple double entries")

    def calculate_unpacked_size(self):
        self.unpacked_size = 0
        for i in self.data.entries:
            self.unpacked_size = max(self.unpacked_size, i.ofs_body, i.len_body)

    labels = [ 'resource', 'appledouble' ]
    metadata = {}
