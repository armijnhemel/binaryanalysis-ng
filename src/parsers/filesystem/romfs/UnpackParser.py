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


import collections
import os
import pathlib

from FileResult import FileResult

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_romfs

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import romfs


#class RomfsUnpackParser(UnpackParser):
class RomfsUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'-rom1fs-')
    ]
    pretty_name = 'romfs'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_romfs(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        # first parse with Kaitai Struct, then with a regular parser.
        # This is because the "next header" points to a byte offset
        # which is not available in Kaitai Struct.
        try:
            self.data = romfs.Romfs.from_io(self.infile)
        except ValidationFailedError as e:
            raise UnpackParserException(e.args)

        next_headers = set()
        for f in self.data.files.files:
            check_condition(f.next_fileheader <= self.data.len_file, "invalid next file header")

            # sanity checks for spec_info, depending on the file type
            if f.filetype == romfs.Romfs.Filetypes.hardlink:
                check_condition(f.spec_info <= self.data.len_file, "invalid spec_info value")
            elif f.filetype == romfs.Romfs.Filetypes.directory:
                check_condition(f.spec_info <= self.data.len_file, "invalid spec_info value")
            elif f.filetype == romfs.Romfs.Filetypes.regular_file:
                check_condition(f.spec_info == 0, "invalid spec_info value")
            elif f.filetype == romfs.Romfs.Filetypes.symbolic_link:
                check_condition(f.spec_info == 0, "invalid spec_info value")
            elif f.filetype == romfs.Romfs.Filetypes.block_device:
                pass
            elif f.filetype == romfs.Romfs.Filetypes.character_device:
                pass
            elif f.filetype == romfs.Romfs.Filetypes.socket:
                check_condition(f.spec_info == 0, "invalid spec_info value")
            elif f.filetype == romfs.Romfs.Filetypes.fifo:
                check_condition(f.spec_info == 0, "invalid spec_info value")

            next_headers.add(f.next_fileheader)

        # now go back to the start of the files and parse again
        self.infile.seek(self.data.files_offset)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.len_file

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'romfs', 'filesystem' ]
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
