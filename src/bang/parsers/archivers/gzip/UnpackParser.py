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

import pathlib
import zlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import gzip as kaitai_gzip


class GzipUnpackParser(UnpackParser):
    extensions = []

    # RFC 1952 says x08 is the only compression method allowed
    signatures = [
        (0, b'\x1f\x8b\x08')
    ]
    pretty_name = 'gzip'

    def parse(self):
        # treat CRC errors as fatal
        wrongcrcfatal = True

        try:
            self.data = kaitai_gzip.Gzip.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # store the CRC and length of the uncompressed data
        gzipcrc32 = zlib.crc32(b'')
        len_uncompressed = 0

        # what follows next is raw deflate blocks. To unpack raw deflate
        # data the windowBits have to be set to negative values:
        # http://www.zlib.net/manual.html#Advanced
        # First create a zlib decompressor that can decompress raw deflate
        # https://docs.python.org/3/library/zlib.html#zlib.compressobj
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

        readsize = 10000000
        checkbuffer = bytearray(readsize)
        self.end_of_header = self.infile.tell()
        total_bytes_read = 0
        while True:
            bytesread = self.infile.readinto(checkbuffer)
            if bytesread == 0:
                break
            checkbytes = memoryview(checkbuffer[:bytesread])
            try:
                unpacked_data = decompressor.decompress(checkbytes)
                len_uncompressed += len(unpacked_data)
                gzipcrc32 = zlib.crc32(unpacked_data, gzipcrc32)
            except Exception as e:
                raise UnpackParserException(e.args)

            total_bytes_read += bytesread - len(decompressor.unused_data)
            if decompressor.unused_data != b'':
                break

        self.infile.seek(self.end_of_header + total_bytes_read)

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
        if self.data.flags.has_name:
            try:
                self.data.name.decode()
            except:
                self.data.flags.has_name = False

    def unpack(self, meta_directory):
        file_path = pathlib.Path("unpacked_from_gzip")
        renamed = False

        # determine the name of the output file
        if self.data.flags.has_name:
            decoded_name = self.data.name.decode()
            if decoded_name != '':
                file_path = pathlib.Path(decoded_name)
                if file_path.is_absolute():
                    file_path = file_path.relative_to('/')
                renamed = True

        if not renamed:
            if meta_directory.file_path.suffix.lower() == '.gz':
                file_path = pathlib.Path(meta_directory.file_path.stem)
                if file_path in ['.', '..']:
                    file_path = pathlib.Path("unpacked_from_gzip")
            elif meta_directory.file_path.suffix.lower() in ['.tgz', '.targz', '.tgzip', '.targzip']:
                file_path = pathlib.Path(meta_directory.file_path.stem + ".tar")
            elif meta_directory.file_path.suffix.lower() == '.svgz':
                file_path = pathlib.Path(meta_directory.file_path.stem + ".svg")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # seek to the start of the zlib compressed data
            self.infile.seek(self.end_of_header)

            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

            readsize = 10000000
            checkbuffer = bytearray(readsize)
            cur_pos = self.infile.tell()
            total_bytes_read = 0
            while True:
                bytesread = self.infile.readinto(checkbuffer)
                if bytesread == 0:
                    break
                checkbytes = memoryview(checkbuffer[:bytesread])
                unpacked_data = decompressor.decompress(checkbytes)
                outfile.write(unpacked_data)

                if decompressor.unused_data != b'':
                    break

            yield unpacked_md

    labels = ['gzip', 'archive']

    @property
    def metadata(self):
        metadata = {}

        if self.data.flags.has_comment:
            try:
                metadata['comment'] = self.data.comment.decode()
            except:
                pass
        return metadata
