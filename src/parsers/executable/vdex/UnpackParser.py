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
from . import vdex

class VdexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'vdex')
    ]
    pretty_name = 'vdex'

    def parse(self):
        try:
            self.data = vdex.Vdex.from_io(self.infile)

            # calculate the length of vdex 027 sections, plus force
            # read the lazily evaluated data
            if self.data.version == '027':
                self.unpacked_size = 0
                for section in self.data.dex_header.sections:
                    if section.len_section != 0:
                        self.unpacked_size = max(self.unpacked_size, section.ofs_section + len(section.section))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        if self.data.version != '027':
            self.unpacked_size = self.infile.tell()

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'vdex']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
