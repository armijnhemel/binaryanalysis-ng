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

'''
Parse and unpack PE files.
'''

import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import microsoft_pe


class PeClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MZ')
    ]
    pretty_name = 'pe'

    def parse(self):
        file_size = self.fileresult.filename.stat().st_size
        self.chunknames = set()
        try:
            self.data = microsoft_pe.MicrosoftPe.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.mz.ofs_pe <= file_size,
                "invalid offset")
        for s in self.data.pe.sections:
            pass

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.mz.ofs_pe
        for s in self.data.pe.sections:
            self.unpacked_size = max(self.unpacked_size, s.size_of_raw_data + s.pointer_to_raw_data)

    def unpack(self):
        """extract any files from the input file"""
        return []

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'pe', 'executable' ]
        metadata = {}

        if self.data.pe.certificate_table is not None:
            for certificate in self.data.pe.certificate_table.items:
                pass

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
