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
Parse GRUB2 font files.
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import grub2_font


class Grub2fontUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FILE\x00\x00\x00\x04PFF2')
    ]
    pretty_name = 'grub2font'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = grub2_font.Grub2Font.from_io(self.infile)
            for i in self.data.sections:
                if i.section_type == 'CHIX':
                    for e in i.body.characters:
                        self.unpacked_size = max(self.unpacked_size,
                                                 e.ofs_definition + 10 + len(e.definition.bitmap_data))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['font', 'resource', 'grub2']
    metadata = {}
