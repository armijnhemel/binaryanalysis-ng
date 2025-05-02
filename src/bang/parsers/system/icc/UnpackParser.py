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
ICC color profile

Specifications: https://www.color.org/specification/ICC.1-2022-05.pdf
chapter 7.

Older specifications:
- https://www.color.org/specification/ICC1v43_2010-12.pdf
- http://www.color.org/icc_specs2.xalter
- https://www.color.org/icc32.pdf

Erratai for 4.3: https://www.color.org/specification/ICC1-2010_Cumulative_Errata_List_2020-10-14.pdf

Test files in package "colord" on for example Fedora
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import icc


class IccUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (36, b'acsp')
    ]
    pretty_name = 'icc'

    def parse(self):
        try:
            self.data = icc.Icc.from_io(self.infile)
            self.unpacked_size = self.infile.tell()
            for tag in self.data.tag_table.tags:
                self.unpacked_size = max(self.unpacked_size, tag.offset_to_data_element + tag.size_of_data_element)
                # force read data
                elem = tag.tag_data_element
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # perhaps there are also padding bytes, as fields
        # are 4 bytes aligned
        if self.unpacked_size % 4 != 0:
            self.infile.seek(self.unpacked_size)
            num_padding = 4 - (self.unpacked_size % 4)
            buf = self.infile.read(num_padding)
            if buf == b'\x00' * num_padding:
                self.unpacked_size += num_padding

    def calculate_unpacked_size(self):
        pass

    labels = ['icc', 'resource']
    metadata = {}
