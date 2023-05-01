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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import git_index


class GitIndexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DIRC')
    ]
    pretty_name = 'git_index'

    def parse(self):
        # parse the file, likely this will fail when carving and there
        # because _io.size and _io.pos are used in the Kaitai Struct
        # definition, which uses the regular file and not the OffsetInputFile
        try:
            self.data = git_index.GitIndex.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # verify the SHA1 checksum
        bytes_to_read = self.infile.tell() - self.data.len_hash

        # seek back to the offset
        self.infile.seek(0)

        # read the bytes
        checksum_bytes = self.infile.read(bytes_to_read)

        # compute the checksum and compare
        checksum = hashlib.sha1(checksum_bytes)
        check_condition(checksum.digest() == self.data.checksum, "invalid checksum")

        # seek to the end of the Git index
        self.infile.seek(self.data.len_hash, os.SEEK_CUR)

    labels = ['git index', 'resource']
    metadata = {}
