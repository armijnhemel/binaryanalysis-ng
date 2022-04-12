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
Parser for ANI files. The parser here is correct, but there are a lot
of ANI files where the length declared in the file is 8 bytes less than
supposed. These files are not correctly recognized.

test files for ANI: http://www.anicursor.com/diercur.html
http://fileformats.archiveteam.org/wiki/Windows_Animated_Cursor#Sample_files
'''

import os

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ani


class AniUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'ACON')
    ]
    pretty_name = 'ani'

    def parse(self):
        try:
            self.data = ani.Ani.from_io(self.infile)
            # force reading of data because of Kaitai's lazy evaluation
            for c in self.data.subchunks:
                chunk_id = c.chunk.id
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ani', 'graphics']
        metadata = {}
        xmptags = []

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
