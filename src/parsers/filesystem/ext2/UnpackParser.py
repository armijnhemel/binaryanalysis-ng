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
import shutil
import subprocess

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_ext2

class Ext2UnpackParser(WrappedUnpackParser):
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

        # parse the superblock

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
