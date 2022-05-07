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
from . import pcapng

class PcapngUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x0a\x0d\x0d\x0a')
    ]
    pretty_name = 'pcapng'

    def parse(self):
        try:
            self.data = pcapng.Pcapng.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        section_header_seen = False
        for block in self.data.blocks:
            if block.header_type == pcapng.Pcapng.HeaderTypes.section_header:
                section_header_seen = True
                break
        check_condition(section_header_seen, "no section header block found")

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['pcapng']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
