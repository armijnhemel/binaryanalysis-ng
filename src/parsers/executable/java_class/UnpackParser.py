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
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_java_class

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import java_class


class JavaClassUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xba\xbe')
    ]
    pretty_name = 'javaclass'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_java_class(fileresult, scan_environment, offset, unpack_dir)

