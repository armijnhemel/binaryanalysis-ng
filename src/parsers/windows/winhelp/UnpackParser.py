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
Parse and unpack Windows Help (.hlp) files.
'''

import os
from UnpackParser import UnpackParser, check_condition, OffsetInputFile
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import winhelp


class WinhelpClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3f\x5f\x03\x00')
    ]
    pretty_name = 'winhelp'

    def parse(self):
        self.file_size = self.fileresult.filesize
        try:
            self.data = winhelp.Winhelp.from_io(self.infile)

            # force read some data
            for i in self.data.internal_directory.contents.leaf_page.entries:
                check_condition(i.ofs_fileheader + i.file.header.len_reserved_space <= self.data.len_file,
                                "leaf entry cannot be outside of file")
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.len_file

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['winhelp', 'resource']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
