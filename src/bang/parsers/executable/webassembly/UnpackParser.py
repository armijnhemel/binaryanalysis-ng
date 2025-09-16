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

# Kaitai file from: https://github.com/evacchi/kaitai-webassembly

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args) from e

    labels = ['webassembly']

    @property
    def metadata(self):
        '''Extract metadata from the WebAssembly file and set labels'''
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

        return metadata
