# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

'''
Parse and unpack Minidump files used in for example Firefox crash reports

https://chromium.googlesource.com/breakpad/breakpad/+/master/src/google_breakpad/common/minidump_format.h
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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

    labels = ['minidump']

    @property
    def metadata(self):
        metadata = {}

        '''
        # TODO: extract interesting information, if any
        for i in self.data.streams:
             if type(i.data) == windows_minidump.WindowsMinidump.SystemInfo:
                 pass
        '''
        return metadata
