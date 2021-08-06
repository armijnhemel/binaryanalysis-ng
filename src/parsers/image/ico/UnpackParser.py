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
from . import ico
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError

class IcoUnpackParser(UnpackParser):
    pretty_name = 'ico'
    extensions = [ '.ico' ]
    signatures = [
        (0, b'\x00\x00\x01\x00')
    ]
    def parse(self):
        try:
            self.data = ico.Ico.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)

        for img in self.data.images:
            try:
                bmp_header = img.bmp
            except (Exception, ValidationNotEqualError) as e:
                raise UnpackParserException(e.args)
            #check_condition(img.num_colors > 0,
                    #"Invalid ico file: zero or negative num_colors")
            check_condition(img.num_planes > 0,
                    "Invalid ico file: zero or negative num_planes")
            check_condition(img.bpp > 0,
                    "Invalid ico file: zero or negative bpp")
            check_condition(img.ofs_img + img.len_img <= self.fileresult.filesize,
                    "Invalid ico file: image outside of file")
            check_condition(img.ofs_img >= 6 + self.data.num_images * 16,
                    "Invalid ico file: image inside header")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.tell() - self.offset
        for i in self.data.images:
            self.unpacked_size = max(self.unpacked_size, i.ofs_img + i.len_img)

    def unpack(self):
        """extract any files from the input file"""
        return []

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['graphics', 'ico', 'resource']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
