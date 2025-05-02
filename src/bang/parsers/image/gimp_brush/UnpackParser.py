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
from . import gimp_brush

from PIL.GbrImagePlugin import GbrImageFile


class GimpBrushUnpackParser(UnpackParser):
    #extensions = ['.gbr']
    extensions = []
    signatures = [
        (20, b'GIMP')
    ]
    pretty_name = 'gimpbrush'

    def calculate_unpacked_size(self):
        try:
            self.unpacked_size = self.data.len_header + self.data.len_body
        except BaseException as e:
            raise UnpackParserException(e.args)

    def parse(self):
        try:
            self.data = gimp_brush.GimpBrush.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.data.header.version < 3, "Invalid version")
        check_condition(self.data.header.version > 0, "Invalid version")
        check_condition(self.data.header.version == 2, "Unsupported version")
        check_condition(self.data.header.width > 0, "Invalid width")
        check_condition(self.data.header.height > 0, "Invalid height")
        check_condition(self.data.len_header > 0, "Invalid header_size")
        unpacked_size = self.data.len_header + self.data.len_body

        check_condition(unpacked_size <= self.infile.size, "Not enough data")
        try:
            self.infile.seek(0)
            testimg = GbrImageFile(self.infile)
            testimg.load()
        except BaseException as e:
            raise UnpackParserException(e.args)

    labels = ['gimp brush', 'graphics']

    @property
    def metadata(self):
        return { 'width': self.data.header.width,
                'height': self.data.header.height,
                'color_depth': self.data.header.bytes_per_pixel.value
            }
