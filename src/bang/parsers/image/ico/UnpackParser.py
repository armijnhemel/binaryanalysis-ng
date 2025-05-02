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

from . import ico


class IcoUnpackParser(UnpackParser):
    pretty_name = 'ico'
    extensions = []
    signatures = [
        (0, b'\x00\x00\x01\x00')
    ]

    def parse(self):
        try:
            self.data = ico.Ico.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)

        for img in self.data.images:
            try:
                bmp_header = img.bmp
                if bmp_header is not None:
                    check_condition(img.width == bmp_header.width,
                                    "width in icon dir and bmp header not matching")
                    check_condition(img.height * 2 == bmp_header.height,
                                    "height in icon dir and bmp header not matching")
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)
            #check_condition(img.num_colors > 0,
                    #"Invalid ico file: zero or negative num_colors")
            # specifications are often not followed for num_planes and bpp:
            # https://devblogs.microsoft.com/oldnewthing/20101018-00/?p=12513
            #check_condition(img.num_planes > 0,
                    #"Invalid ico file: zero or negative num_planes")
            #check_condition(img.bpp > 0,
                    #"Invalid ico file: zero or negative bpp")
            check_condition(img.ofs_img + img.len_img <= self.infile.size,
                    "Invalid ico file: image outside of file")
            check_condition(img.ofs_img >= 6 + self.data.num_images * 16,
                    "Invalid ico file: image inside header")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.tell()
        for i in self.data.images:
            self.unpacked_size = max(self.unpacked_size, i.ofs_img + i.len_img)

    labels = ['graphics', 'ico', 'resource']
    metadata = {}
