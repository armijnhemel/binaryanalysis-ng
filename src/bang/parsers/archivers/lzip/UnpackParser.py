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

import binascii
import lzma
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

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
            except EOFError:
                break
            except Exception as e:
                raise UnpackParserException(e.args) from e

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

    def unpack(self, meta_directory):
        unpacked_files = []
        self.infile.seek(6)

        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.lz':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_lz")
        else:
            file_path = pathlib.Path("unpacked_from_lz")

        # first create a decompressor object
        lzip_filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': self.dictionarysize,
                         'lc': LZMA_LC, 'lp': LZMA_LP, 'pb': LZMA_PB}]

        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=lzip_filters)

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # read and decompress the data
            readsize = 1000000
            lzipbuffer = bytearray(readsize)
            bytesread = self.infile.readinto(lzipbuffer)
            checkbytes = lzipbuffer[:bytesread]

            while bytesread != 0:
                try:
                    unpackeddata = decompressor.decompress(checkbytes)
                    outfile.write(unpackeddata)
                except EOFError:
                    break

                if decompressor.unused_data != b'':
                    # there is no more compressed data
                    break
                bytesread = self.infile.readinto(lzipbuffer)
                checkbytes = lzipbuffer[:bytesread]
            yield unpacked_md

    labels = ['compressed', 'lzip']
    metadata = {}
