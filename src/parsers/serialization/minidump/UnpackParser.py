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
Parse and unpack Minidump files used in for example Firefox crash reports

https://chromium.googlesource.com/breakpad/breakpad/+/master/src/google_breakpad/common/minidump_format.h
'''

import os
from UnpackParser import WrappedUnpackParser
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from bangunpack import unpack_minidump
from . import windows_minidump

#class MinidumpUnpackParser(UnpackParser):
class MinidumpUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'MDMP')
    ]
    pretty_name = 'minidump'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_minidump(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = windows_minidump.WindowsMinidump.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['minidump']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
