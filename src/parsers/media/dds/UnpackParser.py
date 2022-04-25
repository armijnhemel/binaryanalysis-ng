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
from . import dds

class DdsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DDS ')
    ]
    pretty_name = 'dds'

    def parse(self):
        try:
            self.data = dds.Dds.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        compatible_flags = True
        if self.data.dds_header.flags & 0x8 == 0x8 and self.data.dds_header.flags & 0x80000 == 0x80000:
            compatible_flags = False
        check_condition(compatible_flags, "incompatible flags specified")
        check_condition(self.data.dds_header.flags & 0x80000 == 0x80000,
                        "uncompressed files currently not supported")

    def calculate_unpacked_size(self):
        self.unpacked_size = 4 + self.data.dds_header.size + self.data.dds_header.pitch_or_linear_size
        try:
            self.unpacked_size += 20
        except:
            pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['dds', 'graphics']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
