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
Parser for the AU audio format.

Derived from specifications at:
https://en.wikipedia.org/wiki/Au_file_format

Test files in any recent Python 3 distribution in Lib/test/audiodata/ and
http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/AU/Samples.html
'''

import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import au

class AuUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'.snd')
    ]
    pretty_name = 'au'

    def parse(self):
        self.file_size = self.fileresult.filesize
        try:
            self.data = au.Au.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.header.data_size != 0xffffffff,
                        "files with unknown data size not supported")
        check_condition(self.file_size >= self.data.ofs_data + self.data.header.data_size,
                        "not enough data")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.ofs_data + self.data.header.data_size

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'au', 'audio' ]
        metadata = {}
        if self.data.header.comment != '':
            metadata['comment'] = self.data.header.comment

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
