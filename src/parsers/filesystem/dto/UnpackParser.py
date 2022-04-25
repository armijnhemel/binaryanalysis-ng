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
Unpacker for DTBO images. This does not include the AVB signature
at the end.
'''

import os
import pathlib
from FileResult import FileResult
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    # no need to carve the DTBO from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        dtb_counter = 1
        for i in self.data.entries:
            out_labels = []
            file_path = pathlib.Path("unpacked-%d.dtb" % dtb_counter)
            self.extract_to_file(self.rel_unpack_dir / file_path, i.dt_offset, i.dt_size)
            dtb_counter += 1
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files


    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'android', 'dto' ]
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
