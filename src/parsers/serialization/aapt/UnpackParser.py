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

    def unpack(self):
        unpacked_files = []
        out_labels = []

        counter = 1
        for entry in self.data.entries:
            if entry.entry_type == aapt.Aapt.EntryTypes.file:
                entry_file = ResourcesInternal_pb2.CompiledFile()
                entry_file.ParseFromString(entry.data.header)
                file_path = pathlib.Path(entry_file.source_path).name
                outfile_rel = self.rel_unpack_dir / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(entry.data.data)
                fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
                unpacked_files.append(fr)
            elif entry.entry_type == aapt.Aapt.EntryTypes.table:
                table = Resources_pb2.ResourceTable()
                table.ParseFromString(entry.data.data)

                file_path = "table-%d" % counter
                outfile_rel = self.rel_unpack_dir / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(entry.data.data)
                fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
                unpacked_files.append(fr)
                counter += 1

        return unpacked_files


    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['aapt', 'android']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
