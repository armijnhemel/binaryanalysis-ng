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
Unpacker for Mozilla ARchive files.
'''

import os
import pathlib
from FileResult import FileResult
from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError, ValidationGreaterThanError
from . import mozilla_mar


class MozillaMar(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MAR1')
    ]
    pretty_name = 'mar'

    def parse(self):
        file_size = self.infile.size
        try:
            self.data = mozilla_mar.MozillaMar.from_io(self.infile)
        except (Exception, ValidationNotEqualError, ValidationGreaterThanError) as e:
            raise UnpackParserException(e.args)
        except EOFError as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.file_size == self.data.ofs_index + 4 +
                        self.data.index.len_index_entries, "Wrong file size")
        check_condition(self.data.file_size <= file_size, "Not enough data")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.file_size

    def unpack(self, meta_directory):
        for entry in self.data.index.index_entries.index_entry:
            if entry.file_name == '':
                continue

            with meta_directory.unpack_regular_file(pathlib.Path(entry.file_name)) as (unpacked_md, f):
                f.write(entry.content)
                yield unpacked_md

    labels = [ 'mozilla mar' ]
    metadata = {}

