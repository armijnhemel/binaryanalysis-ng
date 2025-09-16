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
from . import dds


class DdsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DDS ')
    ]
    pretty_name = 'dds'

    def parse(self):
        try:
            self.data = dds.Dds.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        compatible_flags = True
        if self.data.dds_header.flags & 0x8 == 0x8 and self.data.dds_header.flags & 0x80000 == 0x80000:
            compatible_flags = False
        check_condition(compatible_flags, "incompatible flags specified")
        check_condition(self.data.dds_header.flags & 0x80000 == 0x80000,
                        "uncompressed files currently not supported")

    def calculate_unpacked_size(self):
        self.unpacked_size = 4 + self.data.dds_header.size + self.data.dds_header.pitch_or_linear_size
        '''
        # likely the above calculation is not entirely correct, but
        # unsure what to do and why the below code was included.
        try:
            self.unpacked_size += 20
        except:
            pass
        '''

    labels = ['dds', 'graphics']
    metadata = {}
