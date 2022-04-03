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
import hashlib
import binascii

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []

        outfile_rel = self.rel_unpack_dir / 'payload'
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.data.payload)
        outfile.close()
        fr = FileResult(self.fileresult, outfile_rel, set())
        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['dhtb', 'android']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
