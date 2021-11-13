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


import hashlib
import os

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import git_index


class GitIndexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DIRC')
    ]
    pretty_name = 'git_index'

    def parse(self):
        try:
            self.data = git_index.GitIndex.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        bytes_to_read = self.infile.tell() - self.offset - self.data.len_hash

        # seek back to the offset
        self.infile.seek(self.offset)
        checksum_bytes = self.infile.read(bytes_to_read)

        checksum = hashlib.sha1(checksum_bytes)
        check_condition(checksum.digest() == self.data.checksum, "invalid checksum")

        self.infile.seek(self.data.len_hash, os.SEEK_CUR)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['git index', 'resource']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
