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
import zstd

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    # no need to carve from the file
    #def carve(self):
    #    pass

    def unpack(self):
        unpacked_files = []

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
                outfile_rel = self.rel_unpack_dir / inode_to_path[inode]
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                outfile_full.mkdir(exist_ok=True)
            else:
                # create the directory of the parent
                outfile_rel = self.rel_unpack_dir / inode_to_path[inode]
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                outfile_full.parent.mkdir(exist_ok=True)

        # now that there is a mapping of inodes to names of files
        # the nodes can be traversed again to find the extra metadata
        # as well as the data blocks belonging to the nodes.
        node_blocks = collections.deque()
        node_blocks.append(self.data.index_root)

        while True:
            try:
                process_node = node_blocks.popleft()
                if type(process_node.node_header) == ubifs.Ubifs.IndexHeader:
                    for branch in process_node.node_header.branches:
                        node_blocks.append(branch.branch_target)
                elif type(process_node.node_header) == ubifs.Ubifs.InodeHeader:
                    inode = process_node.node_header.key.inode_number
                    if inode in inode_to_type:
                        outfile_rel = self.rel_unpack_dir / inode_to_path[inode]
                        if inode_to_type[inode] == ubifs.Ubifs.InodeTypes.regular:
                            # write a stub file
                            outfile_full = self.scan_environment.unpack_path(outfile_rel)
                            outfile = open(outfile_full, 'wb')
                            outfile.close()
                            fr = FileResult(self.fileresult, outfile_rel, set())
                            unpacked_files.append(fr)
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.directory:
                            # directories have already been processed, so skip
                            pass
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.link:
                            outfile_full = self.scan_environment.unpack_path(outfile_rel)
                            try:
                                 target = process_node.node_header.data.decode()
                                 outfile_full.symlink_to(target)
                            except Exception as e:
                                 continue
                            fr = FileResult(self.fileresult, outfile_rel, set(['symbolic link']))
                            unpacked_files.append(fr)
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.block_device:
                            # skip block devices
                            pass
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.character_device:
                            # skip character devices
                            pass
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.fifo:
                            # create fifo
                            outfile_full = self.scan_environment.unpack_path(outfile_rel)
                            os.mkfifo(outfile_full)
                            fr = FileResult(self.fileresult, outfile_rel, set(['fifo']))
                            unpacked_files.append(fr)
                        elif inode_to_type[inode] == ubifs.Ubifs.InodeTypes.socket:
                            # create socket
                            outfile_full = self.scan_environment.unpack_path(outfile_rel)
                            ubi_socket = socket.socket(socket.AF_UNIX)
                            ubi_socket.bind(outfile_full)
                            fr = FileResult(self.fileresult, outfile_rel, set(['socket']))
                            unpacked_files.append(fr)
                elif type(process_node.node_header) == ubifs.Ubifs.DataHeader:
                    inode = process_node.node_header.key.inode_number
                    outfile_rel = self.rel_unpack_dir / inode_to_path[inode]
                    outfile_full = self.scan_environment.unpack_path(outfile_rel)
                    outfile = open(outfile_full, 'ab')
                    if process_node.node_header.compression == ubifs.Ubifs.Compression.no_compression:
                        outfile.write(process_node.node_header.data)
                    elif process_node.node_header.compression == ubifs.Ubifs.Compression.zlib:
                        outfile.write(zlib.decompress(process_node.node_header.data, -zlib.MAX_WBITS))
                    elif process_node.node_header.compression == ubifs.Ubifs.Compression.lzo:
                        outfile.write(lzo.decompress(process_node.node_header.data, False, process_node.node_header.len_uncompressed))
                    elif process_node.node_header.compression == ubifs.Ubifs.Compression.zstd:
                        outfile.write(zstd.decompress(process_node.node_header.data))
                    outfile.close()
            except IndexError:
                break

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ubifs', 'filesystem']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
