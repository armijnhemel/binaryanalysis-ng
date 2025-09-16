# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

from xml.parsers.expat import ExpatError

import defusedxml.minidom

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args) from e

    labels = [ 'wav', 'audio' ]

    @property
    def metadata(self):
        labels = [ 'wav', 'audio' ]
        metadata = {}
        xmptags = []

        # extract metadata
        for chunk in self.data.subchunks:
            if isinstance(chunk.chunk_id,  wav.Wav.Fourcc):
                if chunk.chunk_id == wav.Wav.Fourcc.pmx:
                    try:
                        # XMP should be valid XML
                        xmpdom = defusedxml.minidom.parseString(chunk.chunk_data.data)
                        xmptags.append(chunk.chunk_data.data)
                    except ExpatError:
                        # TODO: what to do here?
                        pass
        if xmptags:
            metadata['xmp'] = xmptags
        return metadata
