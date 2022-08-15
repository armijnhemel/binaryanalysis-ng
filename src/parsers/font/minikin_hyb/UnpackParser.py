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

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import minikin_hyb


class MinikinHybUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x68\x79\xad\x62')
    ]
    pretty_name = 'minikin_hyb'

    def parse(self):
        file_size = self.fileresult.filesize
        try:
            self.data = minikin_hyb.MinikinHyb.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.file_size <= file_size, "invalid file size")
        check_condition(self.data.ofs_alphabet + 4 + self.data.alphabet.alphabet_table.size <= self.data.file_size,
                        "alphabet cannot be outside of file")
        check_condition(self.data.ofs_trie + self.data.trie.size <= self.data.file_size,
                        "trie cannot be outside of file")
        check_condition(self.data.ofs_pattern + self.data.pattern.size <= self.data.file_size,
                        "pattern cannot be outside of file")


    ## make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.file_size

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'resource']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
