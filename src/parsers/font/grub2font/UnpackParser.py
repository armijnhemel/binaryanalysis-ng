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
Parse GRUB2 font files.
'''

import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import grub2_font


class Grub2fontUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FILE\x00\x00\x00\x04PFF2')
    ]
    pretty_name = 'grub2font'

    def parse(self):
        self.file_size = self.fileresult.filesize
        try:
            self.data = grub2_font.Grub2Font.from_io(self.infile)
            for i in self.data.sections:
                if i.section_type == 'CHIX':
                    for e in i.body.characters:
                        self.unpacked_size = max(self.unpacked_size,
                                                 e.ofs_definition + 10 + len(e.definition.bitmap_data))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['font', 'resource', 'grub2']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
