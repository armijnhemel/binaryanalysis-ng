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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import aiff


class AiffUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FORM')
    ]
    pretty_name = 'aiff'

    def parse(self):
        file_size = self.infile.size
        try:
            self.data = aiff.Aiff.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # sanity checks: COMM and SSND chunks are mandatory
        seen_common = False
        seen_ssnd = False
        for chunk in self.data.chunks.chunks:
            if chunk.fourcc == aiff.Aiff.Fourcc.common:
                seen_common = True
            elif chunk.fourcc == aiff.Aiff.Fourcc.ssnd:
                seen_ssnd = True

        check_condition(seen_common, "COMM chunk missing")
        check_condition(seen_ssnd, "SSND chunk missing")

    @property
    def labels(self):
        labels = ['audio', 'aiff']

        if self.data.aiff_type == aiff.Aiff.AiffType.aifc:
            labels.append('aifc')
        return labels

    @property
    def metadata(self):
        metadata = {}
        for chunk in self.data.chunks.chunks:
            if chunk.fourcc == aiff.Aiff.Fourcc.copyright:
                metadata['copyright'] = chunk.data.text
            elif chunk.fourcc == aiff.Aiff.Fourcc.author:
                metadata['author'] = chunk.data.text
            elif chunk.fourcc == aiff.Aiff.Fourcc.name:
                metadata['name'] = chunk.data.text
            elif chunk.fourcc == aiff.Aiff.Fourcc.annotation:
                if 'annotations' not in metadata:
                    metadata['annotations'] = []
                metadata['annotations'].append(chunk.data.text)
        return metadata
