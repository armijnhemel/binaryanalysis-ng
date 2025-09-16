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
import socket
import zlib

import lzo
import zstandard

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ubifs


class UbifsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x31\x18\x10\x06')
    ]
    pretty_name = 'ubifs'

    def parse(self):
        '''Parse ubifs data structure'''
        try:
            self.data = ubifs.Ubifs.from_io(self.infile)

            # store the highest inode number, forces evaluation
            self.highest_inum = self.data.master_1.node_header.highest_inum
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        '''Unpack ubifs data by traversing the tree, starting with the root node'''
        node_blocks = collections.deque()
        node_blocks.append(self.data.index_root)

        # inode to parent, name and type mappings
        parent_to_inodes = {}
        inode_to_name = {}
        inode_to_parent = {}
        inode_to_type = {}

        while True:
            # grab a node to process
            try:
                process_node = node_blocks.popleft()
                if isinstance(process_node.node_header, ubifs.Ubifs.IndexHeader):
                    for branch in process_node.node_header.branches:
                        node_blocks.append(branch.branch_target)
                elif isinstance(process_node.node_header, ubifs.Ubifs.DirectoryHeader):
                    # TODO: use the key for some verification of the inode
                    parent_inode_nr = process_node.node_header.key.inode_number
                    if parent_inode_nr not in parent_to_inodes:
                        parent_to_inodes[parent_inode_nr] = []
                    parent_to_inodes[parent_inode_nr].append(process_node)

                    # target inode number
                    target_inode = process_node.node_header.inode_number
                    target_name = process_node.node_header.name

                    # store name, parent and type
                    inode_to_name[target_inode] = pathlib.Path(target_name)
                    inode_to_parent[target_inode] = parent_inode_nr
                    inode_to_type[target_inode] = process_node.node_header.inode_type
            except IndexError:
                break

        # reconstruct the directory paths per inode
        inode_to_path = {}
        for i in sorted(inode_to_name):
            new_name = inode_to_name[i]
            index = i
            while True:
                if index not in inode_to_parent:
                    inode_to_path[i] = new_name
                    break
                index = inode_to_parent[index]
                if index in inode_to_name:
                    new_name = inode_to_name[index] / new_name

        # create the directories
        for inode in inode_to_path:
            if inode_to_type[inode] == ubifs.Ubifs.InodeTypes.directory:
                meta_directory.unpack_directory(pathlib.Path(inode_to_path[inode]))
            else:
                # create the directory of the parent unless it is empty
                if inode_to_path[inode].parent.name != '':
                    meta_directory.unpack_directory(pathlib.Path(inode_to_path[inode]).parent)

        # now that there is a mapping of inodes to names of files
        # the nodes can be traversed again to find the extra metadata
        # as well as the data blocks belonging to the nodes.
        node_blocks = collections.deque()
        node_blocks.append(self.data.index_root)

        unpacked_mds = {}
        while True:
            try:
                process_node = node_blocks.popleft()
                if isinstance(process_node.node_header, ubifs.Ubifs.IndexHeader):
                    for branch in process_node.node_header.branches:
                        node_blocks.append(branch.branch_target)
                elif isinstance(process_node.node_header, ubifs.Ubifs.InodeHeader):
                    inode = process_node.node_header.key.inode_number
                    if inode in inode_to_type:
                        file_path = pathlib.Path(inode_to_path[inode])
                        if inode_to_type[inode] == ubifs.Ubifs.InodeTypes.regular:
                            # write a stub file
                            # empty file
                            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, f):
                                unpacked_mds[inode] = unpacked_md
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.directory:
                            # directories have already been processed, so skip
                            pass
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.link:
                            try:
                                target = process_node.node_header.data.decode()
                                meta_directory.unpack_symlink(file_path, target)
                                # No meta directory for symlinks
                            except Exception:
                                continue
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.block_device:
                            # skip block devices
                            pass
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.character_device:
                            # skip character devices
                            pass
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.fifo:
                            # create fifo
                            # TODO: let meta_directory create fifo
                            # No meta directory for fifo
                            pass
                            #os.mkfifo(outfile)
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.socket:
                            # create socket
                            # TODO: let meta_directory create socket
                            # No meta directory for socket
                            pass
                            #ubi_socket = socket.socket(socket.AF_UNIX)
                            #ubi_socket.bind(outfile)
                elif isinstance(process_node.node_header, ubifs.Ubifs.DataHeader):
                    inode = process_node.node_header.key.inode_number
                    unpacked_md = unpacked_mds[inode]
                    with open(unpacked_md.abs_file_path, 'ab') as outfile:
                        if process_node.node_header.compression == ubifs.Ubifs.Compression.no_compression:
                            outfile.write(process_node.node_header.data)
                        elif process_node.node_header.compression == ubifs.Ubifs.Compression.zlib:
                            outfile.write(zlib.decompress(process_node.node_header.data, -zlib.MAX_WBITS))
                        elif process_node.node_header.compression == ubifs.Ubifs.Compression.lzo:
                            outfile.write(lzo.decompress(process_node.node_header.data, False, process_node.node_header.len_uncompressed))
                        elif process_node.node_header.compression == ubifs.Ubifs.Compression.zstd:
                            reader = zstandard.ZstdDecompressor().stream_reader(process_node.node_header.data)
                            outfile.write(reader.read())
            except IndexError:
                break

        for unpacked_md in unpacked_mds.values():
            yield unpacked_md

    labels = ['ubifs', 'filesystem']
    metadata = {}
