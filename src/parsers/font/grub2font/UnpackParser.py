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
Parse GRUB2 font files
'''

import os

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import grub2font


from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_grub2font

#class Grub2fontUnpackParser(UnpackParser):
class Grub2fontUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'FILE\x00\x00\x00\x04PFF2')
    ]
    pretty_name = 'grub2font'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_grub2font(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = grub2font.Grub2font.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            print(e)
            raise UnpackParserException(e.args)
        check_condition(self.data.ihdr.bit_depth in [1, 2, 4, 8, 16],
                "invalid bit depth")
