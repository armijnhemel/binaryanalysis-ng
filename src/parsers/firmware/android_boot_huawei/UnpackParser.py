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
from kaitaistruct import ValidationFailedError
from . import android_bootldr_huawei


class AndroidBootHuaweiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3c\xd6\x1a\xce')
    ]
    pretty_name = 'androidboothuawei'

    def parse(self):
        file_size = self.fileresult.filesize
        try:
            self.data = android_bootldr_huawei.AndroidBootldrHuawei.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.meta_header.len_meta_header == 76, "invalid header size")
        self.unpacked_size = 0
        for entry in self.data.image_header.entries:
            self.unpacked_size = max(self.unpacked_size, entry.ofs_body + entry.len_body)
        check_condition(file_size >= self.unpacked_size, "not enough data")


    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        for entry in self.data.image_header.entries:
            if entry.len_body == 0:
                continue
            if entry.name == '':
                continue

            out_labels = []
            file_path = pathlib.Path(entry.name)
            self.extract_to_file(self.rel_unpack_dir / file_path, entry.ofs_body, entry.len_body)
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'bootloader', 'huawei']
        metadata = {}

        metadata['partitions'] = []
        for entry in self.data.image_header.entries:
            if entry.len_body == 0:
                continue
            metadata['partitions'].append({'name': entry.name,
                                           'offset': entry.ofs_body,
                                           'size': entry.len_body})

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
