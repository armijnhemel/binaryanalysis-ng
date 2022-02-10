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
Unpacker for Mozilla ARchive files.
'''

import os
from FileResult import FileResult
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import mozilla_mar


class MozillaMar(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MAR1')
    ]
    pretty_name = 'mar'

    def parse(self):
        file_size = self.fileresult.filesize
        try:
            self.data = mozilla_mar.MozillaMar.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except EOFError as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.file_size == self.data.ofs_index + 4 +
                        self.data.index.len_index_entries, "Wrong file size")
        check_condition(self.data.file_size <= file_size, "Not enough data")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.file_size

    def unpack(self):
        unpacked_files = []
        for entry in self.data.index.index_entries.index_entry:
            if entry.file_name == '':
                continue

            out_labels = []
            outfile_rel = self.rel_unpack_dir / entry.file_name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(entry.content)
            outfile.close()

            fr = FileResult(self.fileresult, outfile_rel, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'mozilla mar' ]
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
