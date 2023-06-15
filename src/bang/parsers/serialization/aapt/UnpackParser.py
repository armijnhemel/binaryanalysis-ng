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

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import aapt

from . import Resources_pb2
from . import ResourcesInternal_pb2


class AaptParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'AAPT')
    ]
    pretty_name = 'aapt'

    def parse(self):
        try:
            self.data = aapt.Aapt.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        for entry in self.data.entries:
            if entry.entry_type == aapt.Aapt.EntryTypes.file:
                try:
                    entry_file = ResourcesInternal_pb2.CompiledFile()
                    entry_file.ParseFromString(entry.data.header)
                except Exception as e:
                    raise UnpackParserException(e.args)
            elif entry.entry_type == aapt.Aapt.EntryTypes.table:
                try:
                    table = Resources_pb2.ResourceTable()
                    table.ParseFromString(entry.data.data)
                except Exception as e:
                    raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        counter = 1
        for entry in self.data.entries:
            if entry.entry_type == aapt.Aapt.EntryTypes.file:
                entry_file = ResourcesInternal_pb2.CompiledFile()
                entry_file.ParseFromString(entry.data.header)
                file_path = pathlib.Path(entry_file.source_path)

                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(entry.data.data)
                    yield unpacked_md

            elif entry.entry_type == aapt.Aapt.EntryTypes.table:
                table = Resources_pb2.ResourceTable()
                table.ParseFromString(entry.data.data)

                file_path = pathlib.Path(f"table-{counter}")
                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(entry.data.data)
                    yield unpacked_md

                counter += 1

    labels = ['aapt', 'android']
    metadata = {}
