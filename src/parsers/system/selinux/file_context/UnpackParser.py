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
from kaitaistruct import ValidationNotEqualError, ValidationNotAnyOfError
from . import file_contexts


class FileContext(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x8a\xff\x7c\xf9')
    ]
    pretty_name = 'file_contexts'

    def parse(self):
        try:
            self.data = file_contexts.FileContexts.from_io(self.infile)
        except (Exception, ValidationNotEqualError, ValidationNotAnyOfError) as e:
            raise UnpackParserException(e.args)


    labels = ['selinux', 'resource']
    metadata = {}

