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

import pathlib

from bang.UnpackParser import UnpackParser
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
            raise UnpackParserException(e.args) from e
        for entry in self.data.entries:
            if entry.entry_type == aapt.Aapt.EntryTypes.file:
                try:
                    entry_file = ResourcesInternal_pb2.CompiledFile()
                    entry_file.ParseFromString(entry.data.header)
                except Exception as e:
                    raise UnpackParserException(e.args) from e
            elif entry.entry_type == aapt.Aapt.EntryTypes.table:
                try:
                    table = Resources_pb2.ResourceTable()
                    table.ParseFromString(entry.data.data)
                except Exception as e:
                    raise UnpackParserException(e.args) from e

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
