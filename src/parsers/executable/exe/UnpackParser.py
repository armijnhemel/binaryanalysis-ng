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
Parse and unpack various DOS/Windows executable formats, namely:

* DOS MZ
* New Executable (NE)
* Portable Executable (PE)

These all have the same signature ('MZ') and because PE and NE
are extensions of DOS MZ it means that files should be checked in
a specific order to recognize from most specific (PE, NE) to least
specific (DOS MZ).
'''

import os
from UnpackParser import UnpackParser, check_condition, OffsetInputFile
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import microsoft_pe
from . import ne
from . import dos_mz
from . import coff

import pefile

class ExeUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MZ')
    ]
    pretty_name = 'exe'

    def parse(self):
        self.file_size = self.fileresult.filesize

        # first try to recognize if a file is a PE.
        # This is the most common case.
        try:
            self.data = microsoft_pe.MicrosoftPe.from_io(self.infile)
            # this is a bit of an ugly hack to detect if the file
            # has been truncated. Also: certain packers screw around
            # with the values of the PE headers
            for s in self.data.pe.sections:
                pass
            if self.data.pe.certificate_table is not None:
                certificate = self.data.pe.optional_hdr.data_dirs.certificate_table

            # calculate the size of the PE. This is somewhat
            # involved as there are multiple headers involved.
            self.unpacked_size = self.data.mz.ofs_pe
            for s in self.data.pe.sections:
                self.unpacked_size = max(self.unpacked_size, s.size_of_raw_data + s.pointer_to_raw_data)

            # certificates, if any, are appended at the end of the file
            if self.data.pe.certificate_table is not None:
                certificate = self.data.pe.optional_hdr.data_dirs.certificate_table
                self.unpacked_size = max(self.unpacked_size, certificate.virtual_address + certificate.size)

            # extra data could follow the PE, such as information
            # from installers or other extra data. It is impossible
            # to get this information from the PE headers, so other
            # tricks need to be found. TODO.

            # then read the data again with the pefile module.
            self.infile.seek(self.offset)
            self.pe = pefile.PE(data=self.infile.read(self.unpacked_size))

            self.exetype = 'pe'
        except (Exception, ValidationFailedError) as e:
            # then try other formats
            check_condition(self.offset == 0, "carving currently not supported")
            try:
                self.infile.seek(self.offset)
                self.data = dos_mz.DosMz.from_io(self.infile)
                self.exetype = 'dos_mz'
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)

        if self.exetype == 'pe':
            check_condition(self.data.mz.ofs_pe <= self.file_size,
                    "invalid offset")
        elif self.exetype == 'dos_mz':
            if self.data.header.mz.last_page_extra_bytes == 0:
                self.end_of_data = self.data.header.mz.num_pages * 512
            else:
                self.end_of_data = (self.data.header.mz.num_pages - 1) * 512 + self.data.header.mz.last_page_extra_bytes
            check_condition(self.end_of_data <= self.fileresult.filesize,
                            "not enough data")

            self.extender = ''
            self.compressed = False
            self.compression = ''

            # it could be that there is extra COFF data after the
            # DOS MZ header and payload, example: many FreeDOS programs
            # some signatures from /usr/share/magic
            self.has_coff = False
            if self.end_of_data + self.offset != self.fileresult.filesize:
                if self.data.body.startswith(b'go32stub, v 2.0'):
                    self.extender = 'DJGPP go32'
                    self.has_coff = True
                elif b'PMODE/W' in self.data.body:
                    self.extender = 'PMODE/W'
                elif b'CauseWay DOS Extender v' in self.data.body:
                    self.extender = 'CauseWay'
                elif b'DOS/32A' in self.data.body:
                    self.extender = 'DOS/32A'
                elif b'DOS/4G' in self.data.body:
                    self.extender = 'DOS4GW'

            # compression
            if b'\x8e\xc0\xb9\x08\x00\xf3\xa5\x4a\x75\xeb\x8e\xc3\x8e\xd8\x33\xff\xbe\x30\x00\x05' in self.data.body:
                self.compressed = True
                self.compression = 'aPack'
            if b'LZ91' in self.data.header.rest_of_header:
                self.compressed = True
                self.compression = 'LZEXE v0.91'

            if self.has_coff:
                self.coff_size = 0
                coff_offset = self.offset + self.end_of_data
                inf = OffsetInputFile(self.infile.infile, coff_offset)
                try:
                    self.coff = coff.Coff.from_io(inf)
                    self.coff_size = inf.tell()
                    for section in self.coff.section_headers:
                        if section.ofs_section != 0:
                            check_condition(section.ofs_section + section.len_section <= self.fileresult.filesize - coff_offset,
                                            "section data outside of file")
                            self.coff_size = max(self.coff_size, section.ofs_section + section.len_section)
                        if section.ofs_relocation_table != 0:
                            check_condition(section.ofs_relocation_table <= self.fileresult.filesize - coff_offset,
                                            "section data outside of file")
                            self.coff_size = max(self.coff_size, section.ofs_relocation_table)
                        if section.ofs_line_number_table != 0:
                            check_condition(section.ofs_line_number_table <= self.fileresult.filesize - coff_offset,
                                            "section data outside of file")
                            self.coff_size = max(self.coff_size, section.ofs_line_number_table)

                    if self.coff.symbol_table_and_string_table is not None:
                        symbol_size = self.coff.header.num_symbols * 18 + self.coff.symbol_table_and_string_table.len_string_table

                        # force read symbols
                        for s in self.coff.symbol_table_and_string_table.string_table.strings:
                            pass
                        self.coff_size = max(self.coff_size, self.coff.header.ofs_symbol_table + symbol_size)
                except (Exception, ValidationFailedError) as e:
                    self.has_coff = False

    def calculate_unpacked_size(self):
        if self.exetype == 'pe':
            # size has already been calculated
            pass
        elif self.exetype == 'dos_mz':
            if not self.has_coff:
                self.unpacked_size = self.end_of_data
            else:
                self.unpacked_size = self.end_of_data + self.coff_size

    def unpack(self):
        """extract any files from the input file"""
        if self.exetype == 'pe':
            # process resources here to extract BMP, ICO, etc.
            pass
        return []

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        metadata = {}

        if self.exetype == 'pe':
            labels = ['pe', 'executable']

            # get the import hash (if any)
            try:
                metadata['imphash'] = self.pe.get_imphash()
            except pefile.PEFormatError:
                pass

            # extract symbols
            metadata['symbols'] = {}
            imported_symbols = {}
            exported_symbols = []

            try:
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    if entry.dll not in imported_symbols:
                        dll = entry.dll.decode()
                        imported_symbols[dll] = []
                    for imp in entry.imports:
                        if imp.name is None:
                            continue
                        imported_symbols[dll].append(imp.name.decode())
            except Exception as e:
                pass

            try:
                for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exported_symbols.append(entry.name.decode())
            except Exception as e:
                pass

            metadata['symbols']['imported'] = imported_symbols
            metadata['symbols']['exported'] = exported_symbols

        elif self.exetype == 'dos_mz':
            labels = ['dos_mz', 'executable']
            if self.compressed:
                metadata['compression'] = self.compression
            if self.has_coff:
                labels.append('coff')
                labels.append('DOS extender')
                if self.coff.symbol_table_and_string_table is not None:
                    metadata['symbol_strings'] = self.coff.symbol_table_and_string_table.string_table.strings
                metadata['extender'] = self.extender

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
