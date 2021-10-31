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
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import windows_minidump

class MinidumpUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MDMP')
    ]
    pretty_name = 'minidump'

    def parse(self):
        try:
            self.data = windows_minidump.WindowsMinidump.from_io(self.infile)
            # this is a bit of an ugly hack as the Kaitai parser is
            # not entirely complete. Use this to detect if the file
            # has been truncated.
            for i in self.data.streams:
                 a = type(i.data)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.ofs_streams
        for i in self.data.streams:
            self.unpacked_size = max(self.unpacked_size, i.ofs_data + i.len_data)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['minidump']
        metadata = {}

        '''
        # TODO: extract interesting information, if any
        for i in self.data.streams:
             if type(i.data) == windows_minidump.WindowsMinidump.SystemInfo:
                 pass
        '''

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
