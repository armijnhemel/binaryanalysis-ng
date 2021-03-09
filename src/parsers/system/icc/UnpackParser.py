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
ICC color profile
Specifications: www.color.org/specification/ICC1v43_2010-12.pdf
chapter 7.

Older specifications: http://www.color.org/icc_specs2.xalter

Test files in package "colord" on for example Fedora
'''


import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_icc

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import icc_v4


#class IccUnpackParser(UnpackParser):
class IccUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (36, b'acsp')
    ]
    pretty_name = 'icc'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_icc(fileresult, scan_environment, offset, unpack_dir)

