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

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import pcap


class PcapUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xd4\xc3\xb2\xa1'),
        (0, b'\xa1\xb2\xc3\xd4'),
        (0, b'\x4d\x3c\xb2\xa1'),
        (0, b'\xa1\xb2\x3c\x4d')
    ]
    pretty_name = 'pcap'

    def parse(self):
        try:
            self.data = pcap.Pcap.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)


    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['pcap']

        metadata = {}
        metadata['count'] = len(self.data.capture.packets)

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
