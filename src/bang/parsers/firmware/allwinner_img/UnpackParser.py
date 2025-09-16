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

import os
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import allwinner_img


class AllwinnerUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'IMAGEWTY')
    ]
    pretty_name = 'allwinner_img'

    def parse(self):
        try:
            self.data = allwinner_img.AllwinnerImg.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e
        check_condition(self.data.img_header.len_image <= self.infile.size, "not enough data")
        self.unpacked_size = 0
        for entry in self.data.file_headers:
            check_condition(entry.file_header_data.stored_length >= entry.file_header_data.original_length,
                            "invalid original/stored length")
            self.unpacked_size = max(self.unpacked_size, entry.file_header_data.offset + entry.file_header_data.stored_length)
        check_condition(self.infile.size >= self.unpacked_size, "not enough data")

    def unpack(self, meta_directory):
        for entry in self.data.file_headers:
            file_path = pathlib.Path(entry.file_header_data.name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                os.sendfile(outfile.fileno(), self.infile.fileno(), entry.file_header_data.offset + self.offset,
                                 entry.file_header_data.original_length)
                yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['allwinner']

    @property
    def metadata(self):
        metadata = {}
        metadata['hardware'] = {}
        metadata['hardware']['usb_product_id'] = self.data.img_header.usb_pid
        metadata['hardware']['usb_vendor_id'] = self.data.img_header.usb_vid
        metadata['hardware']['hardware_id'] = self.data.img_header.hardware_id
        metadata['hardware']['firmware_id'] = self.data.img_header.firmware_id

        metadata['partitions'] = []
        for entry in self.data.file_headers:
            metadata['partitions'].append({'name': entry.file_header_data.name,
                                           'offset': entry.file_header_data.offset,
                                           'size': entry.file_header_data.original_length})
        return metadata
