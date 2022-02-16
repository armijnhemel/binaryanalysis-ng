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


import lzma
import os
import pathlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

class LzmaBaseUnpackParser(UnpackParser):

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
            except EOFError as e:
                break
            except Exception as e:
                # no data could be successfully unpacked
                raise UnpackParserException(e.args)

            self.unpacked_size += bytesread - len(decompressor.unused_data)

            if decompressor.unused_data != b'':
                # there is no more compressed data
                break
            bytesread = self.infile.readinto(checkbuffer)
            buf = memoryview(checkbuffer[:bytesread])

        self.infile.seek(self.unpacked_size)

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        out_labels = []

        if self.filetype == 'xz':
            if self.fileresult.filename.suffix.lower() == '.xz':
                file_path = pathlib.Path(self.fileresult.filename.stem)
            elif self.fileresult.filename.suffix.lower() == '.txz':
                file_path = pathlib.Path(self.fileresult.filename.stem + ".tar")
            else:
                file_path = pathlib.Path("unpacked_from_xz")
        elif self.filetype == 'lzma':
            if self.fileresult.filename.suffix.lower() == '.lzma':
                file_path = pathlib.Path(self.fileresult.filename.stem)
            elif self.fileresult.filename.suffix.lower() == '.tlz':
                file_path = pathlib.Path(self.fileresult.filename.stem + ".tar")
            else:
                file_path = pathlib.Path("unpacked_from_lzma")

        # open the output file
        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        # seek to the start of the zlib compressed data
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

        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [self.filetype, 'compressed']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)


class LzmaUnpackParser(LzmaBaseUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5d\x00\x00'),
        (0, b'\x6d\x00\x00'),
        (0, b'\x6c\x00\x00'),
        (0, b'\x6e\x00\x00'),
    ]
    pretty_name = 'lzma'


class XzUnpackParser(LzmaBaseUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xfd\x37\x7a\x58\x5a\x00')
    ]
    pretty_name = 'xz'

