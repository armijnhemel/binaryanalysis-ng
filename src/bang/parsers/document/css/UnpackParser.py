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

import tinycss2

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class CssUnpackParser(UnpackParser):
    extensions = ['.css']
    signatures = [
    ]
    pretty_name = 'css'

    def parse(self):
        # tinycss2 cannot process files that should be carved
        check_condition(False, "unsupported")
        try:
            self.data = tinycss2.parse_stylesheet_bytes(self.infile.read())
        except Exception as e:
            raise UnpackParserException(e.args)

    labels = ['css']
    metadata = {}
