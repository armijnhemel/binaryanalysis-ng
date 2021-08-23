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
import collections
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
        print(self.data.index_root)

    # no need to carve from the file
    #def carve(self):
    #    pass

    def unpack(self):
        # start with the root index and traverse

        node_blocks = collections.deque()
        node_blocks.append(self.data.index_root)

        # put all the inodes here. The root inode is typically 64
        inodes = {}

        while True:
          # grab a node to process
          try:
              process_node = node_blocks.popleft()
              if type(process_node.node_header) == ubifs.Ubifs.IndexHeader:
                  for branch in process_node.node_header.branches:
                      node_blocks.append(branch.branch_target)
              elif type(process_node.node_header) == ubifs.Ubifs.DirectoryHeader:
                  # TODO: use the key for some verification of the inode
                  #print('inode nr', process_node.node_header.inode_number)
                  #print('inode name', process_node.node_header.name)
                  print('inode type', process_node.node_header.key.type)
                  print('inode key', process_node.node_header.key.value)
                  sys.stdout.flush()
              elif type(process_node.node_header) == ubifs.Ubifs.InodeHeader:
                  sys.stdout.flush()
              elif type(process_node.node_header) == ubifs.Ubifs.DataHeader:
                  sys.stdout.flush()
              else:
                  print(type(process_node.node_header))
                  sys.stdout.flush()
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
