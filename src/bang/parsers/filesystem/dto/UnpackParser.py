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
Unpacker for device tree overlay (DTO) images, also called DTBO. This does
not include the AVB signature at the end.
'''

import os
import pathlib
from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_dto


class AndroidDtoUnpacker(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xd7\xb7\xab\x1e')
    ]
    pretty_name = 'dto'

    def parse(self):
        try:
            self.data = android_dto.AndroidDto.from_io(self.infile)
            # this is a bit of an ugly hack as the Kaitai parser is
            # not entirely complete. Use this to detect if the file
            # has been truncated.
            #a = type(self.data.buddy_allocator_body)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = 0
        for i in self.data.entries:
            self.unpacked_size = max(self.unpacked_size, i.dt_offset + i.dt_size)

    def unpack(self, meta_directory):
        dtb_counter = 1
        for i in self.data.entries:
            file_path = pathlib.Path("unpacked-%d.dtb" % dtb_counter)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                os.sendfile(outfile.fileno(), self.infile.fileno(), self.offset + i.dt_offset, i.dt_size)
                dtb_counter += 1
                yield unpacked_md

    labels = ['android', 'dto']
    metadata = {}
