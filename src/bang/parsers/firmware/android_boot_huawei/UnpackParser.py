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

import os
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_bootldr_huawei


class AndroidBootHuaweiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3c\xd6\x1a\xce')
    ]
    pretty_name = 'androidboothuawei'

    def parse(self):
        try:
            self.data = android_bootldr_huawei.AndroidBootldrHuawei.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e
        check_condition(self.data.meta_header.len_meta_header == 76, "invalid header size")
        self.unpacked_size = 0
        for entry in self.data.image_header.entries:
            self.unpacked_size = max(self.unpacked_size, entry.ofs_body + entry.len_body)
        check_condition(self.infile.size >= self.unpacked_size, "not enough data")

    def unpack(self, meta_directory):
        for entry in self.data.image_header.entries:
            if entry.len_body == 0:
                continue
            if entry.name == '':
                continue

            out_labels = []
            file_path = pathlib.Path(entry.name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, f):
                os.sendfile(f.fileno(), self.infile.fileno(), self.offset + entry.ofs_body, entry.len_body)
                yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['android', 'bootloader', 'huawei']

    @property
    def metadata(self):
        metadata = {}
        metadata['partitions'] = []
        for entry in self.data.image_header.entries:
            if entry.len_body == 0:
                continue
            metadata['partitions'].append({'name': entry.name,
                                           'offset': entry.ofs_body,
                                           'size': entry.len_body})
        return metadata
