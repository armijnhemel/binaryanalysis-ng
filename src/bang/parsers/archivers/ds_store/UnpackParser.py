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
Unpacker for Apple .DS_Store files, frequently found in archives
created on MacOS.
'''

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ds_store


class DSStoreUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (4, b'Bud1')
    ]
    pretty_name = 'dstore'

    def parse(self):
        try:
            self.data = ds_store.DsStore.from_io(self.infile)
            # this is a bit of an ugly hack as the Kaitai parser is
            # not entirely complete. Use this to detect if the file
            # has been truncated.
            a = type(self.data.buddy_allocator_body)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.buddy_allocator_header.ofs_bookkeeping_info_block + \
                            self.data.buddy_allocator_header.len_bookkeeping_info_block + 4

    labels = ['resource', 'ds_store']
    metadata = {}
