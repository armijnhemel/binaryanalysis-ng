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

# https://www.fileformat.info/format/sunraster/egff.htm
# This is an imperfect parser: only some formats are supported
# and there could be false positives.

import os

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

        check_condition(32 + self.data.len_color_map + self.data.len_image_data <= self.fileresult.filesize,
                        "not enough data")
        self.unpacked_size = 32 + self.data.len_color_map + self.data.len_image_data

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def extract_metadata_and_labels(self):
        labels = ['raster', 'graphics', 'sun raster']
        metadata = {}
        return (labels, metadata)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        (labels, metadata) = self.extract_metadata_and_labels()
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
