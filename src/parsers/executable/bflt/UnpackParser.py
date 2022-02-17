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

# bFLT is an old format used on uClinux systems.

import os
import zlib

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import bflt
from parsers.archivers.gzip import gzip as kaitai_gzip


class BfltUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'bFLT')
    ]
    pretty_name = 'bflt'

    def parse(self):
        # notes: it could be that for GOT binaries some
        # of the offsets are incorrect (TODO).
        # gzdata is not yet supported.
        try:
            self.data = bflt.Bflt.from_io(self.infile)
            self.unpacked_size = self.infile.tell()

            if self.data.header.gzip:
                # interestingly, sometimes the "multipart gzip"
                # flag has been set (TODO)
                start_of_gzip = self.infile.tell()
                try:
                    gzip_data = kaitai_gzip.Gzip.from_io(self.infile)
                except (Exception, ValidationFailedError) as e:
                    raise UnpackParserException(e.args)

                gzipcrc32 = zlib.crc32(b'')

                # decompress the data
                decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                len_uncompressed = 0

                readsize = 10000000
                checkbuffer = bytearray(readsize)
                end_of_header = self.infile.tell()
                total_bytes_read = 0
                unpacked_data = b''
                while True:
                    bytesread = self.infile.readinto(checkbuffer)
                    if bytesread == 0:
                        break
                    checkbytes = memoryview(checkbuffer[:bytesread])
                    try:
                        unpacked_data += decompressor.decompress(checkbytes)
                        len_uncompressed += len(unpacked_data)
                        gzipcrc32 = zlib.crc32(unpacked_data, gzipcrc32)
                    except Exception as e:
                        raise UnpackParserException(e.args)

                    total_bytes_read += bytesread - len(decompressor.unused_data)
                    if decompressor.unused_data != b'':
                        break

                self.infile.seek(end_of_header + total_bytes_read)

                # then the CRC32 of the uncompressed data (RFC 1952, section 2.3.1)
                checkbytes = self.infile.read(4)

                check_condition(gzipcrc32 == int.from_bytes(checkbytes, byteorder='little'),
                                "wrong CRC")

                # compute the ISIZE (RFC 1952, section 2.3.1)
                checkbytes = self.infile.read(4)

                # this check is modulo 2^32
                isize = len_uncompressed % pow(2, 32)
                check_condition(isize == int.from_bytes(checkbytes, byteorder='little'),
                                "wrong value for ISIZE")

                self.unpacked_size = self.infile.tell()

                # verify the offsets from the bFLT header with the *uncompressed* data
                check_condition(self.data.header.ofs_data_end + start_of_gzip <= len_uncompressed + start_of_gzip,
                                "data section cannot be outside of file")
                check_condition(self.data.header.ofs_reloc_start + self.data.header.reloc_count * 4 <= len_uncompressed + start_of_gzip,
                                "data section cannot be outside of file")

                rel_offset = self.data.header.ofs_reloc_start - start_of_gzip
                for r in range(self.data.header.reloc_count):
                    reloc = int.from_bytes(unpacked_data[rel_offset + r*4:rel_offset + r*4+4], byteorder='big')
                    # likely incorrect when relocations are in other
                    # files, for example shared libraries
                    check_condition(reloc <= len_uncompressed + start_of_gzip,
                                      "relocation cannot be outside of file")

                # make data and text sections available for further processing
                rel_data_offset = self.data.header.ofs_data_start - start_of_gzip
                rel_text_offset = self.data.header.ofs_entry - start_of_gzip
                self.data_data = unpacked_data[rel_data_offset:rel_data_offset + self.data.len_data]
                self.data_text = unpacked_data[rel_text_offset:rel_text_offset + self.data.len_text]

            else:
                self.unpacked_size = self.data.header.ofs_entry + len(self.data.data)

                if self.data.header.gzdata:
                    pass
                else:
                    self.unpacked_size = self.data.header.ofs_reloc_start
                    for r in self.data.relocations.relocation:
                        self.unpacked_size += 4

                        # likely incorrect when relocations are in other
                        # files, for example shared libraries
                        check_condition(r <= self.fileresult.filesize,
                                        "relocation cannot be outside of file")
                    self.data_data = self.data.data
                    self.data_text = self.data.text
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

        if self.data_data is not None:
            for s in self.data_data.split(b'\x00'):
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

        if self.data_text is not None:
            for s in self.data_text.split(b'\x00'):
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
