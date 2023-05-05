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

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import gdfw


class GdfwUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'GDFW')
    ]
    pretty_name = 'gdfw'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = gdfw.Gdfw.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        if self.data.header.len_hostfw != 0:
            file_path = pathlib.Path('hostfw')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.hostfw)
                yield unpacked_md

        if self.data.header.len_gcfw != 0:
            file_path = pathlib.Path('gcfw')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.hostfw)
                yield unpacked_md

    labels = ['gdfw', 'firmware']
    metadata = {}
