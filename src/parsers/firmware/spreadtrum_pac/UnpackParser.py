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
from . import spreadtrum_pac


class SpreadtrumPacUnpackParser(UnpackParser):
    extensions = ['.pac']
    signatures = []
    pretty_name = 'spreadtrum_pac'

    def parse(self):
        try:
            self.data = spreadtrum_pac.SpreadtrumPac.from_io(self.infile)
            self.unpacked_size = self.data.header.len_file
            for entry in self.data.entries.entries:
                self.unpacked_size = max(self.unpacked_size, entry.header.ofs_partition + entry.header.len_partition)
                len_data = len(entry.data)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.fileresult.filesize >= self.unpacked_size, "not enough data")

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self, unpack_directory):
        unpacked_files = []

        for entry in self.data.entries.entries:
            if entry.header.len_partition == 0:
                continue
            out_labels = []

            file_path = entry.header.file_name.decode('utf-16-le').split('\x00')[0]

            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(entry.data)
            outfile.close()
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['spreadtrum', 'firmware']

        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
