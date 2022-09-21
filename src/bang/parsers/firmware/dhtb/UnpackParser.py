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

import binascii
import hashlib
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import dhtb


class DhtbUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DHTB\x01\x00\x00\x00')
    ]
    pretty_name = 'dhtb'

    def parse(self):
        try:
            self.data = dhtb.Dhtb.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        sha256 = hashlib.sha256(self.data.payload)
        check_condition(sha256.hexdigest() == binascii.hexlify(self.data.header.sha256).decode(),
                        'invalid hash')

    def unpack(self, meta_directory):
        unpacked_files = []

        file_path = pathlib.Path('payload')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.payload)
            yield unpacked_md

    labels = ['dhtb', 'android']
    metadata = {}
