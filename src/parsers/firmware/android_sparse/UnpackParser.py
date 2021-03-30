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
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import android_sparse


import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_sparse

#class AndroidSparseUnpackParser(UnpackParser):
class AndroidSparseUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3a\xff\x26\xed')
    ]
    pretty_name = 'androidsparse'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_sparse(fileresult, scan_environment, offset, unpack_dir)

