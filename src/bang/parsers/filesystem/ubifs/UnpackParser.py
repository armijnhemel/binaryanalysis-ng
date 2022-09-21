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
import zlib
import collections
import socket

import lzo
import zstandard

from bang.UnpackParser import UnpackParser, check_condition
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
        try:
            self.data = ubifs.Ubifs.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):

        # store the highest inode number
        highest_inum = self.data.master_1.node_header.highest_inum

        # traverse the tree, starting with the root inode
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
                if type(process_node.node_header) == ubifs.Ubifs.IndexHeader:
                    for branch in process_node.node_header.branches:
                        node_blocks.append(branch.branch_target)
                elif type(process_node.node_header) == ubifs.Ubifs.DirectoryHeader:
                    # TODO: use the key for some verification of the inode
                    parent_inode_nr = process_node.node_header.key.inode_number
                    if parent_inode_nr not in parent_to_inodes:
                        parent_to_inodes[parent_inode_nr] = []
                    parent_to_inodes[parent_inode_nr].append(process_node)

                    # target inode number
                    target_inode = process_node.node_header.inode_number
                    target_name = process_node.node_header.name

                    # store name, parent and type
                    inode_to_name[target_inode] = target_name
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
                    new_name = os.path.join(inode_to_name[index], new_name)

        # create the directories
        for inode in inode_to_path:
            if inode_to_type[inode] == ubifs.Ubifs.InodeTypes.directory:
                meta_directory.unpack_directory(pathlib.Path(inode_to_path[inode]))
            else:
                # create the directory of the parent
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
                if type(process_node.node_header) == ubifs.Ubifs.IndexHeader:
                    for branch in process_node.node_header.branches:
                        node_blocks.append(branch.branch_target)
                elif type(process_node.node_header) == ubifs.Ubifs.InodeHeader:
                    inode = process_node.node_header.key.inode_number
                    file_path = pathlib.Path(inode_to_path[inode])
                    if inode in inode_to_type:
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
                            except Exception as e:
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
                            #outfile_full = self.scan_environment.unpack_path(outfile_rel)
                            #os.mkfifo(outfile_full)
                            #fr = FileResult(self.fileresult, outfile_rel, set(['fifo']))
                            #unpacked_files.append(fr)
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.socket:
                            # create socket
                            # TODO: let meta_directory create socket
                            # No meta directory for socket
                            pass
                            #outfile_full = self.scan_environment.unpack_path(outfile_rel)
                            #ubi_socket = socket.socket(socket.AF_UNIX)
                            #ubi_socket.bind(outfile_full)
                            #fr = FileResult(self.fileresult, outfile_rel, set(['socket']))
                            #unpacked_files.append(fr)
                elif type(process_node.node_header) == ubifs.Ubifs.DataHeader:
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
