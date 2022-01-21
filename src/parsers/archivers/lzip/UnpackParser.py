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


import binascii
import lzma
import os
import pathlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

# hardcoded LZMA properties
LZMA_LC = 3
LZMA_LP = 0
LZMA_PB = 2

class LzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'LZIP')
    ]
    pretty_name = 'lzip'

    # http://www.nongnu.org/lzip/manual/lzip_manual.html#File-format
    def parse(self):
        # skip the magic bytes
        self.infile.seek(4)

        # LZIP version should always be 1
        version = ord(self.infile.read(1))
        check_condition(version == 1, "invalid lzip version")

        # then the LZMA dictionary size. The lowest 5 bits are
        # the dictionary base size.
        checkbytes = self.infile.read(1)
        dictionary_base = pow(2, ord(checkbytes) & 31)
        self.dictionarysize = dictionary_base - dictionary_base//16 * (ord(checkbytes) >> 5)

        # create a LZMA decompressor with custom filter, as the data is
        # stored without LZMA headers. The LZMA properties are hardcoded
        # for lzip, except the dictionary.
        lzip_filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': self.dictionarysize,
                         'lc': LZMA_LC, 'lp': LZMA_LP, 'pb': LZMA_PB}]

        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=lzip_filters)

        # while decompressing also compute the CRC of the uncompressed
        # data, as it is stored after the compressed LZMA data in the file
        crc_computed = binascii.crc32(b'')

        pos = self.infile.tell()

        # read and decompress the data, compute CRC
        readsize = 1000000
        lzipbuffer = bytearray(readsize)
        bytesread = self.infile.readinto(lzipbuffer)
        checkbytes = lzipbuffer[:bytesread]
        decompressed_size = 0

        while bytesread != 0:
            try:
                unpackeddata = decompressor.decompress(checkbytes)
                decompressed_size += len(unpackeddata)
            except EOFError as e:
                break
            except Exception as e:
                raise UnpackParserException(e.args)

            crc_computed = binascii.crc32(unpackeddata, crc_computed)

            pos += bytesread - len(decompressor.unused_data)

            if decompressor.unused_data != b'':
                # there is no more compressed data
                break
            bytesread = self.infile.readinto(lzipbuffer)
            checkbytes = lzipbuffer[:bytesread]

        # first seek to the end of the decompressed data
        self.infile.seek(pos)

        # read and check the stored CRC
        checkbytes = self.infile.read(4)
        crc_stored = int.from_bytes(checkbytes, byteorder='little')
        check_condition(crc_stored == crc_computed, "CRC mismatch")

        # read and check the stored uncompressed size
        checkbytes = self.infile.read(8)
        uncompressed_size = int.from_bytes(checkbytes, byteorder='little')
        check_condition(uncompressed_size == decompressed_size,
                        "uncompressed size mismatch")

        # read and check the stored member size
        checkbytes = self.infile.read(8)
        member_size = int.from_bytes(checkbytes, byteorder='little')
        check_condition(member_size == pos + 20, "member size mismatch")


    def unpack(self):
        unpacked_files = []
        self.infile.seek(6)

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.lz':
            file_path = pathlib.Path(self.fileresult.filename.stem)
        else:
            file_path = pathlib.Path("unpacked_from_lz")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        # first create a decompressor object
        lzip_filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': self.dictionarysize,
                         'lc': LZMA_LC, 'lp': LZMA_LP, 'pb': LZMA_PB}]

        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=lzip_filters)

        # read and decompress the data
        readsize = 1000000
        lzipbuffer = bytearray(readsize)
        bytesread = self.infile.readinto(lzipbuffer)
        checkbytes = lzipbuffer[:bytesread]

        while bytesread != 0:
            try:
                unpackeddata = decompressor.decompress(checkbytes)
                outfile.write(unpackeddata)
            except EOFError as e:
                break

            if decompressor.unused_data != b'':
                # there is no more compressed data
                break
            bytesread = self.infile.readinto(lzipbuffer)
            checkbytes = lzipbuffer[:bytesread]

        outfile.close()
        fr = FileResult(self.fileresult, outfile_rel, set())
        unpacked_files.append(fr)
        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['compressed', 'lzip']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
