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
Parse and unpack Preferred Executable Format (PEF) files,
as used on classic MacOS.
'''

import os
from UnpackParser import UnpackParser, check_condition, OffsetInputFile
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import pef


class PefClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'Joy!peff'),
    ]
    pretty_name = 'pef'

    def parse(self):
        self.file_size = self.fileresult.filesize
        try:
            self.data = pef.Pef.from_io(self.infile)

            self.unpacked_size = self.infile.tell()

            # force read part of the sections
            for s in self.data.section_headers:
                self.unpacked_size = max(self.unpacked_size, s.ofs_container + s.len_packed)
                if s.section_kind != pef.Pef.Section.loader:
                    check_condition(len(s.section) == s.len_packed,
                                    "not enough data")
                else:
                    symbols = s.section.header.symbols
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['pef', 'executable', 'macos']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
