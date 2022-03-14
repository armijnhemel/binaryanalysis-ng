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

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_cramfs

class CramfsUnpackParser(WrappedUnpackParser):
#class CramfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x45\x3d\xcd\x28'),
        (0, b'\x28\xcd\x3d\x45')
    ]
    pretty_name = 'cramfs'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_cramfs(fileresult, scan_environment, offset, unpack_dir)

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['cramfs', 'filesystem']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
