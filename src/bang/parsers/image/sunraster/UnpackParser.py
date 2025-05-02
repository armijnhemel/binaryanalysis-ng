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

# https://www.fileformat.info/format/sunraster/egff.htm
# This is an imperfect parser: only some formats are supported
# and there could be false positives.
#
# Sample file: https://www.fileformat.info/format/sunraster/sample/index.htm

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import sunraster


class SunrasterUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x59\xa6\x6a\x95')
    ]
    pretty_name = 'sunraster'

    def parse(self):
        try:
            self.data = sunraster.Sunraster.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.data.len_image_data != 0,
                        "raster files with length 0 defined not supported")

        # only support standard types for now
        check_condition(self.data.bitmap_type == sunraster.Sunraster.BitmapTypes.standard,
                        "only standard type is supported")

        check_condition(32 + self.data.len_color_map + self.data.len_image_data <= self.infile.size,
                        "not enough data")
        self.unpacked_size = 32 + self.data.len_color_map + self.data.len_image_data

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['raster', 'graphics', 'sun raster']
    metadata = {}
