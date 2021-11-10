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
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_romfs

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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
        try:
            self.data = romfs.Romfs.from_io(self.infile)
        except (UnicodeDecodeError, ValueError, ValidationFailedError) as e:
            # TODO: ValueError should be caught in .ksy? (len_file - _io.pos cannot be negative)
            raise UnpackParserException(e.args)
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

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.len_file

    labels = [ 'romfs', 'filesystem' ]
    metadata = {}

