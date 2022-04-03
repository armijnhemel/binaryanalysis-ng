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
        check_condition(self.unpacked_size <= self.fileresult.filesize, "data outside file")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'imgdata']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
