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

# Kaitai file from: https://github.com/evacchi/kaitai-webassembly

import os

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import webassembly


class WebAssemblyUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00asm')
    ]
    pretty_name = 'webassembly'

    def parse(self):
        try:
            self.data = webassembly.Webassembly.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def extract_metadata_and_labels(self):
        '''Extract metadata from the WebAssembly file and set labels'''
        labels = ['webassembly']
        metadata = {}

        function_imports = []
        function_exports = []

        for section in self.data.sections.sections:
            if section.header.id == webassembly.Webassembly.PayloadType.import_payload:
                for entry in section.payload_data.entries:
                    if entry.kind == webassembly.Webassembly.KindType.function_kind:
                        function_imports.append({'module': entry.module_str, 'name': entry.field_str})
            elif section.header.id == webassembly.Webassembly.PayloadType.export_payload:
                for entry in section.payload_data.entries:
                    if entry.kind == webassembly.Webassembly.KindType.function_kind:
                        function_exports.append(entry.field_str)
            elif section.header.id == webassembly.Webassembly.PayloadType.data_payload:
                for entry in section.payload_data.entries:
                    pass

        metadata['exports'] = function_exports
        metadata['imports'] = function_imports

        return (labels, metadata)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        (labels, metadata) = self.extract_metadata_and_labels()
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
