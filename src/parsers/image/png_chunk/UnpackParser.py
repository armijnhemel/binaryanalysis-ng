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
Parse and unpack PNG chunks. The specification of the PNG format can be found
at:

https://www.w3.org/TR/PNG/

Section 5 describes the structure of a PNG file
'''

import os
import binascii

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import png_chunk

# a list of known chunks
KNOWN_CHUNKS = set([b'IHDR', b'IDAT', b'IEND', b'PLTE', b'bKGD', b'cHRM',
                    b'gAMA', b'hIST', b'iCCP', b'pHYs', b'sBIT', b'sPLT',
                    b'sRGB', b'tEXt', b'tIME', b'tRNS', b'zTXt', b'iTXt',
                    b'acTL', b'fcTL', b'fdAT', b'npTc', b'npLb', b'npOl',
                    b'oFFs', b'vpAg', b'caNv', b'pCAL', b'tXMP', b'iDOT',
                    b'prVW', b'mkBT', b'mkBS', b'mkTS', b'mkBF', b'orNT',
                    b'sCAL', b'sTER', b'meTa', b'grAb', b'alPh', b'huBs',
                    b'ptIc', b'snAp', b'viSt', b'pcLs', b'raNd', b'dSIG',
                    b'eXIf', b'eXif', b'skMf', b'skRf'])


class PngUnpackParser(UnpackParser):
    extensions = []
    signatures = list(map(lambda x: (4, x), KNOWN_CHUNKS))
    pretty_name = 'png_chunk'

    def parse(self):
        try:
            self.data = png_chunk.PngChunk.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        computed_crc = binascii.crc32(self.data.chunk.type.encode('utf-8'))

        # hack for text chunks, where 'body' is text and not bytes
        try:
            computed_crc = binascii.crc32(self.data.chunk._raw_body, computed_crc)
        except:
            computed_crc = binascii.crc32(self.data.chunk.body, computed_crc)
        check_condition(computed_crc == int.from_bytes(self.data.chunk.crc, byteorder='big'),
                "invalid CRC")

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'png_chunk', 'partial']
        metadata = {}
        metadata['name'] = self.data.chunk.type

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
