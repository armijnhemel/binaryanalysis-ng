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

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError, ValidationNotAnyOfError
from . import sgi

from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_sgi


#class SgiUnpackParser(UnpackParser):
class SgiUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x01\xda')
    ]
    pretty_name = 'sgi'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_sgi(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.unpacked_size = 0
            self.data = sgi.Sgi.from_io(self.infile)
            if self.data.header.storage_format != 0:
                for i in range(0, len(self.data.body.start_table_entries)):
                    self.unpacked_size = max(self.unpacked_size, self.data.body.start_table_entries[i] + self.data.body.length_table_entries[i])
                for scanline in self.data.body.scanlines:
                    # read data because Kaitai Struct evaluates instances lazily
                    len_data = len(scanline.data)
                check_condition(self.unpacked_size <= self.infile.size,
                            "data cannot be outside of file")
            else:
                self.unpacked_size = self.infile.tell()
        except (Exception, ValidationNotEqualError, ValidationNotAnyOfError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    # TODO: rename carved file, if a name was embedded in the file
    #def unpack(self):
    #    unpacked_files = []

    labels = ['graphics', 'sgi']
    metadata = {}

