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

'''
ICC color profile
Specifications: www.color.org/specification/ICC1v43_2010-12.pdf
chapter 7.

Errata: https://www.color.org/specification/ICC1-2010_Cumulative_Errata_List_2020-10-14.pdf

Older specifications: http://www.color.org/icc_specs2.xalter
https://www.color.org/icc32.pdf

Test files in package "colord" on for example Fedora
'''


import os

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import icc


class IccUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (36, b'acsp')
    ]
    pretty_name = 'icc'

    def parse(self):
        try:
            self.data = icc.Icc.from_io(self.infile)
            self.unpacked_size = self.infile.tell()
            for tag in self.data.tag_table.tags:
                self.unpacked_size = max(self.unpacked_size, tag.offset_to_data_element + tag.size_of_data_element)
                # force read data
                elem = tag.tag_data_element
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # perhaps there are also padding bytes, as fields
        # are 4 bytes aligned
        if self.unpacked_size % 4 != 0:
            self.infile.seek(self.offset + self.unpacked_size)
            num_padding = 4 - (self.unpacked_size % 4)
            buf = self.infile.read(num_padding)
            if buf == b'\x00' * num_padding:
                self.unpacked_size += num_padding

    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['icc', 'resource']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
