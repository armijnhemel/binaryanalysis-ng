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
from . import qt_resource

class QtResourceUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'qres'),
    ]
    pretty_name = 'qt_resource'

    def parse(self):
        try:
            self.data = qt_resource.QtResource.from_io(self.infile)
            for entry in self.data.name_table.entries:
                name = entry.name.decode('utf-16-be')
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(len(self.data.data_block.entries) == len(self.data.name_table.entries),
                        "amount of names and files do not match")


    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []

        counter = 0
        for entry in self.data.data_block.entries:
            out_labels = []

            file_path = self.data.name_table.entries[counter].name.decode('utf-16-be')

            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(entry.data)
            outfile.close()
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
            counter += 1
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['qt', 'resource']

        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
