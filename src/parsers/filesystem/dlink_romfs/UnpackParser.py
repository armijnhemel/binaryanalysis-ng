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
import lzma
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import dlink_romfs

class DlinkRomfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (16, b'ROMFS v9')
    ]
    pretty_name = 'dlinkromfs'

    def parse(self):
        try:
            self.data = dlink_romfs.DlinkRomfs.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = 0
        ct = 0
        for entry in self.data.entries:
            self.unpacked_size = max(self.unpacked_size, entry.ofs_entry + entry.len_entry)
        check_condition(self.fileresult.filesize >= self.unpacked_size, "not enough data")

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []

        # first reconstruct all the paths, before writing any data
        entry_to_path = {0: pathlib.Path('')}
        for entry in self.data.entries:
            if entry.is_directory:
                curpath = entry_to_path[entry.entry_id_block.entry_id]
                for dir_entry in entry.data.dir_entries:
                    if dir_entry.name in ['.', '..']:
                        continue
                    entry_to_path[dir_entry.directory_id] = curpath / dir_entry.name

        # go through all inodes again, but now write the data
        for entry in self.data.entries:
            out_labels = []
            if entry.entry_id_block.entry_id == 0:
                continue
            file_path = entry_to_path[entry.entry_id_block.entry_id]
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)

            if entry.is_directory:
                out_labels.append('directory')
                os.makedirs(outfile_full, exist_ok=True)
            elif entry.is_regular:
                outfile = open(outfile_full, 'wb')
                if entry.is_compressed:
                    outfile.write(lzma.decompress(entry.data))
                else:
                    outfile.write(entry.data)
                outfile.close()
            elif entry.is_symlink:
                out_labels.append('symbolic link')
                try:
                    target = entry.data.decode()
                    outfile_full.symlink_to(target)
                except UnicodeDecodeError:
                    continue
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)

        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['d-link', 'filesystem']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
