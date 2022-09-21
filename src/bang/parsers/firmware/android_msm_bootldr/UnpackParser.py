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
Extract bootloader files as found on Qualcomm Snapdragon (MSM)
based Android devices.
'''

import os
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_bootldr_qcom


class AndroidMsmBootldrUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BOOTLDR!')
    ]
    pretty_name = 'androidmsmboot'

    def parse(self):
        try:
            self.data = android_bootldr_qcom.AndroidBootldrQcom.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        self.unpacked_size = self.data.ofs_img_bodies
        for entry in self.data.img_headers:
            self.unpacked_size += entry.len_body
        check_condition(self.infile.size >= self.unpacked_size, "not enough data")

    def unpack(self, meta_directory):
        cur_offset = self.data.ofs_img_bodies
        for entry in self.data.img_headers:
            if entry.len_body == 0:
                continue
            if entry.name == '':
                cur_offset += entry.len_body
                continue

            file_path = pathlib.Path(entry.name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, f):
                os.sendfile(f.fileno(), self.infile.fileno(), cur_offset, entry.len_body)
                yield unpacked_md
            cur_offset += entry.len_body

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['android', 'bootloader', 'qualcomm']

    @property
    def metadata(self):
        metadata = {}

        metadata['chipset'] = 'snapdragon'
        metadata['partitions'] = []
        cur_offset = self.data.ofs_img_bodies
        # TODO: we can put this info on the unpacked_md info too?
        for entry in self.data.img_headers:
            if entry.len_body == 0:
                continue
            metadata['partitions'].append({'name': entry.name,
                                           'offset': cur_offset,
                                           'size': entry.len_body})
            cur_offset += entry.len_body

        return metadata
