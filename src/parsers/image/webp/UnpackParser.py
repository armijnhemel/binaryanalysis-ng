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

# http://binary-analysis.blogspot.com/2018/06/walkthrough-webp-file-format.html

import os

import defusedxml

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import webp

class WebpUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'WEBP')
    ]
    pretty_name = 'webp'

    def parse(self):
        try:
            self.data = webp.Webp.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self):
        """extract any files from the input file"""
        return []

    def extract_metadata_and_labels(self):
        '''Extract metadata from the WebP file and set labels'''
        labels = ['webp', 'graphics']
        metadata = {}

        chunk_names = []
        xmp_data = []
        for chunk in self.data.payload.chunks:
            chunk_names.append(chunk.name.name)

            if chunk.name == webp.Webp.ChunkNames.xmp:
                try:
                    # XMP should be valid XML
                    xmpdom = defusedxml.minidom.parseString(chunk.data.data)
                    xmp_data.append(chunk.data.data)
                except:
                    pass

        metadata['chunks'] = chunk_names
        if xmp_data != []:
            metadata['xmp'] = xmp_data

        return(labels, metadata)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        metadata = {}

        (labels, metadata) = self.extract_metadata_and_labels()
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
