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

from xml.parsers.expat import ExpatError

import defusedxml.minidom

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import riff
from . import wav

class WavUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'WAVE')
    ]
    pretty_name = 'wav'

    def parse(self):
        try:
            self.data = wav.Wav.from_io(self.infile)
            # force reading of data because of Kaitai's lazy evaluation
            for c in self.data.subchunks:
                chunk_id = c.chunk.id
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'wav', 'audio' ]
        metadata = {}
        xmptags = []

        # extract metadata
        for chunk in self.data.subchunks:
            if type(chunk.chunk_id) == wav.Wav.Fourcc:
                if chunk.chunk_id == wav.Wav.Fourcc.pmx:
                    try:
                        # XMP should be valid XML
                        xmpdom = defusedxml.minidom.parseString(chunk.chunk_data.data)
                        xmptags.append(chunk.chunk_data.data)
                    except ExpatError:
                        # TODO: what to do here?
                        pass
        metadata['xmp'] = xmptags

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
