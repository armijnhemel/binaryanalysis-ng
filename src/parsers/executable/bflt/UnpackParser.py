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
from bangunpack import unpack_bflt

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import bflt


class BfltUnpackParser(WrappedUnpackParser):
#class BfltUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'bFLT')
    ]
    pretty_name = 'bflt'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bflt(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = bflt.Bflt.from_io(self.infile)
            self.unpacked_size = self.infile.tell()

            if self.data.header.gzip:
                pass
            else:
               self.unpacked_size = self.data.header.ofs_entry + len(self.data.data)

               if self.data.header.gzdata:
                   pass
               else:
                  self.unpacked_size = self.data.header.ofs_reloc_start
                  for r in self.data.relocations.relocation:
                      self.unpacked_size += 4
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    #def carve(self):
        #pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def extract_metadata_and_labels(self):
        '''Extract metadata from the ELF file and set labels'''
        labels = ['bflt', 'executable']
        metadata = {}
        data_strings = []
        string_cutoff_length = 4

        # translation table for ASCII strings
        string_translation_table = str.maketrans({'\t': ' '})

        for s in self.data.data.split(b'\x00'):
            try:
                decoded_strings = s.decode().splitlines()
                for decoded_string in decoded_strings:
                    if len(decoded_string) < string_cutoff_length:
                        continue
                    if decoded_string.isspace():
                        continue
                    translated_string = decoded_string.translate(string_translation_table)
                    if decoded_string.isascii():
                        # test the translated string
                        if translated_string.isprintable():
                            data_strings.append(decoded_string)
                    else:
                        data_strings.append(decoded_string)
            except:
                pass

        metadata['strings'] = data_strings
        return (labels, metadata)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        (labels, metadata) = self.extract_metadata_and_labels()
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
