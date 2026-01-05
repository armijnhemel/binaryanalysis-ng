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

import collections
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import romfs


class RomfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'-rom1fs-')
    ]
    pretty_name = 'romfs'

    def parse(self):
        # first parse with Kaitai Struct, then with a regular parser.
        # This is because the "next header" points to a byte offset
        # which is not available in Kaitai Struct.
        try:
            self.data = romfs.Romfs.from_io(self.infile)
        except (UnicodeDecodeError, ValidationFailedError, Exception) as e:
            raise UnpackParserException(e.args) from e

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

        # and a mapping from offsets to current names (used for hard links)
        self.offset_to_name = {}

        # keep a deque with which offset/parent directory pairs
        offsets = collections.deque()

        # then the file headers, with data
        curoffset = self.infile.tell()
        curcwd = pathlib.Path('')
        offsets.append((curoffset, curcwd))

        # now keep processing offsets, until none
        # are left to process.
        while True:
            # wrap, parse single kaitaistruct.from_io()
            try:
                (curoffset, curcwd) = offsets.popleft()
            except:
                break
            self.infile.seek(curoffset)
            file_header = romfs.Romfs.Fileheader.from_io(self.infile)
            check_condition(self.infile.tell() <= self.data.len_file,
                            "file cannot be outside of romfs")

            if file_header.name not in set(['.', '..']):
                self.offset_to_name[curoffset] = curcwd / file_header.name

            if file_header.filetype == romfs.Romfs.Filetypes.hardlink:
                # hard link, target is in spec.info
                if file_header.name not in set(['.', '..']):
                    check_condition(file_header.spec_info in self.offset_to_name, "invalid link")
            elif file_header.filetype == romfs.Romfs.Filetypes.directory:
                # directory: the next header points to the first file header.
                if file_header.name not in set(['.', '..']):
                    offsets.append((file_header.spec_info, curcwd / file_header.name))
            elif file_header.filetype == romfs.Romfs.Filetypes.regular_file:
                pass
            elif file_header.filetype == romfs.Romfs.Filetypes.symbolic_link:
                try:
                    file_header.data.decode()
                except UnicodeDecodeError as e:
                    raise UnpackParserException(e.args) from e
            elif file_header.filetype == romfs.Romfs.Filetypes.block_device:
                pass
            elif file_header.filetype == romfs.Romfs.Filetypes.character_device:
                pass
            elif file_header.filetype == romfs.Romfs.Filetypes.socket:
                pass
            elif file_header.filetype == romfs.Romfs.Filetypes.fifo:
                pass

            if file_header.next_fileheader != 0:
                offsets.append((file_header.next_fileheader, curcwd))

    def unpack(self, meta_directory):
        unpacked_files = []

        # now go back to the start of the files and unpack
        self.infile.seek(self.data.files_offset)

        # keep a deque with which offset/parent directory pairs
        offsets = collections.deque()

        # then the file headers, with data
        curoffset = self.infile.tell()
        curcwd = pathlib.Path('')
        offsets.append((curoffset, curcwd))

        # now keep processing offsets, until none
        # are left to process.
        while True:
            # wrap, parse single kaitaistruct.from_io()
            try:
                (curoffset, curcwd) = offsets.popleft()
            except:
                break
            self.infile.seek(curoffset)
            file_header = romfs.Romfs.Fileheader.from_io(self.infile)

            if file_header.filetype == romfs.Romfs.Filetypes.hardlink:
                # hard link, target is in spec.info
                if file_header.name not in set(['.', '..']):

                    # grab the name of the target, turn it into a full path
                    source_target_name = self.offset_to_name[file_header.spec_info]
                    if source_target_name.is_absolute():
                        source_target_name = source_target_name.relative_to('/')

                    file_path = curcwd / file_header.name

                    # link source and target
                    meta_directory.unpack_hardlink(file_path, source_target_name)

            elif file_header.filetype == romfs.Romfs.Filetypes.directory:
                if file_header.name not in set(['.', '..']):
                    file_path = curcwd / file_header.name
                    meta_directory.unpack_directory(file_path)
                    offsets.append((file_header.spec_info, curcwd / file_header.name))
            elif file_header.filetype == romfs.Romfs.Filetypes.regular_file:
                file_path = curcwd / file_header.name
                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(file_header.data)
                    yield unpacked_md
            elif file_header.filetype == romfs.Romfs.Filetypes.symbolic_link:
                target = file_header.data.decode()
                file_path = curcwd / file_header.name
                meta_directory.unpack_symlink(file_path, target)
            elif file_header.filetype == romfs.Romfs.Filetypes.block_device:
                pass
            elif file_header.filetype == romfs.Romfs.Filetypes.character_device:
                pass
            elif file_header.filetype == romfs.Romfs.Filetypes.socket:
                pass
            elif file_header.filetype == romfs.Romfs.Filetypes.fifo:
                pass

            if file_header.next_fileheader != 0:
                offsets.append((file_header.next_fileheader, curcwd))

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.len_file

        # romfs file systems are aligned on a 1024 byte boundary
        if self.data.len_file % 1024 != 0:
            len_padding = 1024 - self.data.len_file % 1024

            # verify that the padding bytes are actually padding
            self.infile.seek(self.data.len_file)
            padding = self.infile.read(len_padding)
            if padding == b'\x00' * len_padding:
                self.unpacked_size += len_padding

    labels = [ 'romfs', 'filesystem' ]
    metadata = {}
