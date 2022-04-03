# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only


import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import gimp_brush

from PIL.GbrImagePlugin import GbrImageFile


class GimpBrushUnpackParser(UnpackParser):
    extensions = ['.gbr']
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

        check_condition(unpacked_size <= self.fileresult.filesize, "Not enough data")
        try:
            self.infile.seek(0)
            testimg = GbrImageFile(self.infile)
            testimg.load()
        except BaseException as e:
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        self.unpack_results.set_labels(['gimp brush', 'graphics'])
        self.unpack_results.set_metadata({'width': self.data.header.width,
                                           'height': self.data.header.height,
                                           'color_depth': self.data.header.bytes_per_pixel.value
                                        })
