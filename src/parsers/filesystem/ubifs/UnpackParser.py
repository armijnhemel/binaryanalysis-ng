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
import sys
import pathlib
import zlib
import collections

import lzo

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
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
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    #def carve(self):
    #    pass

    def unpack(self):
        # store the highest inode number
        highest_inum = self.data.master_1.node_header.highest_inum

        # traverse the tree, starting with the root inode
        node_blocks = collections.deque()
        node_blocks.append(self.data.index_root)

        # inode to parent and name mappings
        parent_to_inodes = {}
        inode_to_name = {}
        inode_to_parent = {}

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
                  inode_to_name[target_inode] = target_name
                  inode_to_parent[target_inode] = parent_inode_nr
          except IndexError:
              break

        # reconstruct the directory paths per inode
        inode_to_paths = {}
        for i in sorted(inode_to_name):
            new_name = inode_to_name[i]
            index = i
            while True:
                if index not in inode_to_parent:
                    inode_to_paths[i] = new_name
                    break
                index = inode_to_parent[index]
                if index in inode_to_name:
                    new_name = os.path.join(inode_to_name[index], new_name)

        # now that there is a mapping of inodes to names of files
        # the nodes can be traversed again to find the extra metadata
        # as well as the data blocks belonging to the nodes.
        node_blocks = collections.deque()
        node_blocks.append(self.data.index_root)

        while True:
          cur_open = None
          cur_file = None
          try:
              process_node = node_blocks.popleft()
              if type(process_node.node_header) == ubifs.Ubifs.IndexHeader:
                  for branch in process_node.node_header.branches:
                      node_blocks.append(branch.branch_target)
              elif type(process_node.node_header) == ubifs.Ubifs.DirectoryHeader:
                  if process_node.node_header.inode_type == ubifs.Ubifs.InodeTypes.directory:
                      # create the directory
                      outfile_rel = self.rel_unpack_dir / inode_to_paths[process_node.node_header.inode_number]
                      outfile_full = self.scan_environment.unpack_path(outfile_rel)
                      outfile_full.mkdir()
              elif type(process_node.node_header) == ubifs.Ubifs.InodeHeader:
                  pass
              elif type(process_node.node_header) == ubifs.Ubifs.DataHeader:
                  pass
          except IndexError:
              break

        unpacked_files = []
        for entry in self.data.file_headers:
            out_labels = []
            file_path = pathlib.Path(entry.name)
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(entry.data)
            outfile.close()
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ubifs', 'filesystem']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
