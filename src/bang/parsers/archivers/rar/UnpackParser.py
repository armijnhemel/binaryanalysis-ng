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
import re
import subprocess

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import rar


class RarUnpackParser(UnpackParser):
    pretty_name = 'rar'
    signatures = [
            (0, b'Rar!\x1a\x07'),
    ]
    def parse(self):
        raise UnpackParserException("Rar not supported")
        try:
            self.data = rar.Rar.from_io(self.infile)
        except (BaseException, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
    def unpack(self, unpack_directory):
        return []
        # TODO: (?) for multifile rar only process the .rar file and let it
        # search for .r00, .r01 etc. (these must be written to disk before
        # processing starts, which I assume is the case)
        # skip processing for .r00, etc.
        # To print file names:
        # for b in self.data.blocks:
        #    if b.block_type == self.data.BlockTypes.file_header:
        #        print(b.body.file_name)

    @classmethod
    def is_valid_extension(cls, ext):
        return ext == '.rar' or re.match(r'\.r\d\d', ext)


