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
Unpacker for PCF font files. Specifications can be found at:

https://fontforge.org/docs/techref/pcf-format.html

Unfortunately there seem to be many files that do not follow the
specification:

https://github.com/kaitai-io/kaitai_struct_formats/issues/437
'''

import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import pcf_font

class PcfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x01fcp')
    ]
    pretty_name = 'pcf'

    def parse(self):
        try:
            self.data = pcf_font.PcfFont.from_io(self.infile)
            check_condition(self.data.num_tables > 0,
                            "invalid number of tables")
            # this is a bit of an ugly hack to detect if the file
            # has been truncated.
            for i in self.data.tables:
                 a = type(i.body)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve the PCF font from the file
    def carve(self):
        pass

    def calculate_unpacked_size(self):
        self.unpacked_size = 0
        for t in self.data.tables:
            self.unpacked_size = max(self.unpacked_size, t.len_body + t.ofs_body)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['pcf', 'font']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
