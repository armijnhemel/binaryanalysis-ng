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

import lzma
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class LzmaBaseUnpackParser(UnpackParser):
    pretty_name = 'lzma_base'

    def __init__(self, from_meta_directory, offset, configuration):
        super().__init__(from_meta_directory, offset, configuration)
        self.from_md = from_meta_directory

    def parse(self):
        buf = self.infile.read(6)
        if buf == b'\xfd\x37\x7a\x58\x5a\x00':
            self.filetype = 'xz'
        else:
            self.filetype = 'lzma'

            # There are many false positives for LZMA.
            # The file lzma-file-format.txt in XZ file distributions describe
            # the LZMA format. The first 13 bytes describe the header. The last
            # 8 bytes of the header describe the file size.
            self.infile.seek(5)
            buf = self.infile.read(8)

            check_condition(len(buf) == 8, "not enough data for size field")

            # first check if an actual length of the *uncompressed* data is
            # stored, or if it is possibly stored as a stream. LZMA streams
            # have 0xffffffff stored in the length field.
            # http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
            if buf != b'\xff\xff\xff\xff\xff\xff\xff\xff':
                lzmaunpackedsize = int.from_bytes(buf, byteorder='little')
                check_condition(lzmaunpackedsize != 0, "declared size 0")

                # XZ Utils cannot unpack or create files > 256 GiB
                check_condition(lzmaunpackedsize <= 274877906944, "declared size too big")

        # seek to the start of the file again
        self.infile.seek(0)
        self.unpacked_size = 0

        # unpack incrementally, as described in the Python documentation:
        # https://docs.python.org/3/library/bz2.html#incremental-de-compression
        # https://docs.python.org/3/library/lzma.html
        decompressor = lzma.LZMADecompressor()
        checkbuffer = bytearray(900000)

        bytesread = self.infile.readinto(checkbuffer)
        buf = memoryview(checkbuffer[:bytesread])
        while bytesread != 0:
            try:
                decompressor.decompress(buf)
            except EOFError:
                break
            except Exception as e:
                # no data could be successfully unpacked
                raise UnpackParserException(e.args) from e

            self.unpacked_size += bytesread - len(decompressor.unused_data)

            if decompressor.unused_data != b'':
                # there is no more compressed data
                break
            bytesread = self.infile.readinto(checkbuffer)
            buf = memoryview(checkbuffer[:bytesread])

        self.infile.seek(self.unpacked_size)

    def unpack(self, meta_directory):
        if self.filetype == 'xz':
            if meta_directory.file_path.suffix.lower() == '.xz':
                file_path = pathlib.Path(meta_directory.file_path.stem)
                if file_path in ['.', '..']:
                    file_path = pathlib.Path("unpacked_from_xz")
            elif meta_directory.file_path.suffix.lower() in ['.txz', '.tarxz']:
                file_path = pathlib.Path(meta_directory.file_path.stem + ".tar")
            else:
                file_path = pathlib.Path("unpacked_from_xz")

            # overwrite in case another name was given
            propagated_info = self.from_md.info.get('propagated', {})
            if 'name' in propagated_info:
                file_path = pathlib.Path(propagated_info['name'])
        elif self.filetype == 'lzma':
            if meta_directory.file_path.suffix.lower() in ['.lzma', '.lz']:
                file_path = pathlib.Path(meta_directory.file_path.stem)
                if file_path in ['.', '..']:
                    file_path = pathlib.Path("unpacked_from_lzma")
            elif meta_directory.file_path.suffix.lower() in ['.tlz', '.tarlz', '.tarlzma']:
                file_path = pathlib.Path(meta_directory.file_path.stem + ".tar")
            else:
                file_path = pathlib.Path("unpacked_from_lzma")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # seek to the start of the lzma or xz compressed data
            self.infile.seek(0)
            decompressor = lzma.LZMADecompressor()
            checkbuffer = bytearray(900000)

            bytesread = self.infile.readinto(checkbuffer)
            buf = memoryview(checkbuffer[:bytesread])
            while bytesread != 0:
                unpacked_data = decompressor.decompress(buf)
                outfile.write(unpacked_data)

                if decompressor.unused_data != b'':
                    break
                bytesread = self.infile.readinto(checkbuffer)
                buf = memoryview(checkbuffer[:bytesread])

            yield unpacked_md

    @property
    def labels(self):
        labels = [self.filetype, 'compressed']
        return labels

    metadata = {}


class LzmaUnpackParser(LzmaBaseUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5d\x00\x00'),
        (0, b'\x6d\x00\x00'), # used in OpenWrt
        (0, b'\x6c\x00\x00'), # some routers, like ZyXEL NBG5615, use this
        (0, b'\x6e\x00\x00'),
    ]
    pretty_name = 'lzma'


class XzUnpackParser(LzmaBaseUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xfd\x37\x7a\x58\x5a\x00')
    ]
    pretty_name = 'xz'
