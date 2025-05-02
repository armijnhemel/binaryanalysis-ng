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
from . import vdex


class VdexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'vdex')
    ]
    pretty_name = 'vdex'

    def parse(self):
        try:
            self.data = vdex.Vdex.from_io(self.infile)

            # calculate the length of vdex 027 sections, plus force
            # read the lazily evaluated data
            if self.data.version == '027':
                self.unpacked_size = 0
                for section in self.data.dex_header.sections:
                    if section.len_section != 0:
                        self.unpacked_size = max(self.unpacked_size, section.ofs_section + len(section.section))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        if self.data.version != '027':
            self.unpacked_size = self.infile.tell()

    labels = ['android', 'vdex']
    metadata = {}
