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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import erofs


class ErofsUnpacker(UnpackParser):
    extensions = []
    signatures = [
        (1024, b'\xe2\xe1\xf5\xe0')
    ]
    pretty_name = 'erofs'

    def parse(self):
        try:
            self.data = erofs.Erofs.from_io(self.infile)

            # force read the data to force Kaitai Struct to evaluate
            nr_of_blocks = len(self.data.blocks)

            # walk the inodes
            inodes = collections.deque()
            inodes.append(('', '', erofs.Erofs.FileTypes.directory, self.data.root_inode))
            while True:
                try:
                    name, parent, file_type, inode = inodes.popleft()

                    # only process "inline" inodes for now
                    check_condition(inode.inode_layout == erofs.Erofs.Inode.Layouts.inline,
                                    "only inline inodes supported for now")

                    if inode.inode.is_dir:
                        check_condition(file_type == erofs.Erofs.FileTypes.directory,
                                            "directory not declared as directory")
                        # recurse into the directory tree
                        for d in inode.data.dir_entries.entries:
                            if d.name.name in ['.', '..']:
                                # sanity check: make sure these are tagged as 'directory'
                                check_condition(d.file_type == erofs.Erofs.FileTypes.directory,
                                                "directory not declared as directory")
                                continue
                            inodes.append((d.name.name, name, d.file_type, d.inode))
                    elif inode.inode.is_regular:
                        check_condition(file_type == erofs.Erofs.FileTypes.regular_file,
                                            "directory not declared as directory")
                        # force read the data to force Kaitai Struct to evaluate
                        d = inode.data.node_data
                    elif inode.inode.is_link:
                        check_condition(file_type == erofs.Erofs.FileTypes.symlink,
                                            "directory not declared as directory")
                except IndexError:
                    break
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.superblock.header.len_file

    def unpack(self, meta_directory):
        inodes = collections.deque()
        inodes.append(('', '', erofs.Erofs.FileTypes.directory, self.data.root_inode))
        while True:
            try:
                name, parent, file_type, inode = inodes.popleft()
                file_path = pathlib.Path(parent, name)

                if inode.inode.is_dir:
                    if file_path.name != '':
                        meta_directory.unpack_directory(file_path)

                    # recurse into the directory tree
                    for d in inode.data.dir_entries.entries:
                        if d.name.name in ['.', '..']:
                            continue
                        inodes.append((d.name.name, name, d.file_type, d.inode))
                elif inode.inode.is_regular:
                    with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                        outfile.write(inode.data.node_data)
                        outfile.write(inode.data.last_inline_data)
                        yield unpacked_md
                elif inode.inode.is_link:
                    target = pathlib.Path(inode.data.link_data)
                    meta_directory.unpack_symlink(file_path, target)

            except IndexError:
                break

    labels = ['erofs', 'filesystem']

    @property
    def metadata(self):
        metadata = {'uuid': self.data.superblock.header.uuid}
        metadata['name'] = self.data.superblock.header.volume_name
        return metadata
