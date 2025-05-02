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
from . import android_imgdata


# test file hammerhead-krt16m-factory-fb4041cc.zip
class AndroidImgdataUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'IMGDATA!')
    ]
    pretty_name = 'android_imgdata'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = android_imgdata.AndroidImgdata.from_io(self.infile)
            for image in self.data.images:
                self.unpacked_size = max(self.unpacked_size, image.ofs_image + image.len_image)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.unpacked_size <= self.infile.size, "data outside file")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['android', 'imgdata']
    metadata = {}
