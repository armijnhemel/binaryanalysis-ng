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


import math
import os
import shutil
import subprocess
import tempfile
import uuid

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_ext2

from . import ext2

class Ext2UnpackParser(WrappedUnpackParser):
#class Ext2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x438,  b'\x53\xef')
    ]
    pretty_name = 'ext2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ext2(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        check_condition(shutil.which('e2ls') is not None, "e2ls program not found")
        check_condition(shutil.which('e2cp') is not None, "e2cp program not found")

        self.infile.seek(1024)

        # parse the superblock
        try:
            self.superblock = ext2.Ext2.SuperBlockStruct.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.superblock.block_size * self.superblock.blocks_count <= self.fileresult.filesize,
                        "declared file system size larger than file size")

        # does this have to be math.ceil()?
        block_groups = math.ceil(self.superblock.blocks_count/self.superblock.blocks_per_group)
        self.unpacked_size = self.superblock.block_size * self.superblock.blocks_count

        # extract a volume name if present
        try:
            self.volume_name = self.superblock.volume_name.decode()
        except:
            self.volume_name = ""

        # extract a last mounted path if present
        try:
            self.last_mounted = self.superblock.last_mounted.decode()
        except:
            self.last_mounted = ""

        self.fs_uuid = uuid.UUID(bytes=self.superblock.uuid)

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ext2', 'filesystem']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
