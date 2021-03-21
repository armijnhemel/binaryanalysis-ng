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
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_elf
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import elf


#class ElfUnpackParser(UnpackParser):
class ElfUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x7f\x45\x4c\x46')
    ]
    pretty_name = 'elf'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_elf(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        self.chunknames = set()
        try:
            self.data = elf.Elf.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'elf' ]
        metadata = {'security': []}

        # keep track of whether or not GNU_RELRO has been set
        seen_relro = False

        for header in self.data.header.program_headers:
            if header.type == elf.Elf.PhType.gnu_relro:
                metadata['security'].append('relro')
                seen_relro = True
            elif header.type == elf.Elf.PhType.gnu_stack:
                # check to see if NX is set
                if not header.flags_obj.execute:
                    metadata['security'].append('nx')
            elif header.type == elf.Elf.PhType.pax_flags:
                metadata['security'].append('pax')

        is_dynamic_elf = False
        for header in self.data.header.section_headers:
            if header.name in ['.modinfo', '__ksymtab_strings']:
                labels.append('linuxkernelmodule')
            elif header.name in ['oat_patches', '.text.oat_patches']:
                labels.append('oat')
                labels.append('android')
            if header.type == elf.Elf.ShType.dynamic:
                is_dynamic_elf = True
            elif header.type == elf.Elf.ShType.note:
                for h in header.body.entries:
                    pass
                if header.name == '.note.go.buildid':
                    labels.append('go')

        if is_dynamic_elf:
            labels.append('dynamic')
        else:
            labels.append('static')

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
