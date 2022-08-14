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
import pathlib
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args)
        check_condition(self.data.img_header.len_image + self.offset <= self.fileresult.filesize, "not enough data")
        self.unpacked_size = 0
        for entry in self.data.file_headers:
            check_condition(entry.file_header_data.stored_length >= entry.file_header_data.original_length,
                            "invalid original/stored length")
            self.unpacked_size = max(self.unpacked_size, entry.file_header_data.offset + entry.file_header_data.stored_length)
        check_condition(self.fileresult.filesize >= self.unpacked_size, "not enough data")


    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        for entry in self.data.file_headers:
            out_labels = []
            file_path = pathlib.Path(entry.file_header_data.name)
            self.extract_to_file(self.rel_unpack_dir / file_path,
                                 entry.file_header_data.offset,
                                 entry.file_header_data.original_length)
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['allwinner']
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

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
