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

# https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md

import os
import pathlib
import zstandard

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class ZstdUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x28\xb5\x2f\xfd')
    ]
    pretty_name = 'zstd'

    def __init__(self, from_meta_directory, offset, configuration):
        super().__init__(from_meta_directory, offset, configuration)
        self.from_md = from_meta_directory

    def parse(self):
        # skip the magic
        self.infile.seek(4)

        # then read the frame header descriptor as it might indicate
        # whether or not there is a size field.
        buf = self.infile.read(1)
        check_condition(len(buf) == 1, "not enough data for zstd frame header")

        if ord(buf) & 32 == 0:
            is_single_segment = False
        else:
            is_single_segment = True

        # process the frame header descriptor to see how big the
        # frame header is.
        frame_content_size_flag = ord(buf) >> 6
        if frame_content_size_flag == 3:
            fcs_field_size = 8
        elif frame_content_size_flag == 2:
            fcs_field_size = 4
        elif frame_content_size_flag == 1:
            fcs_field_size = 2
        else:
            # now it depends on the single_segment_flag
            if not is_single_segment:
                fcs_field_size = 0
            else:
                fcs_field_size = 1

        # reserved bit MUST 0
        check_condition(ord(buf) & 8 == 0, "reserved bit set")

        # content checksum flag
        content_checksum_set = False
        if ord(buf) & 4 == 4:
            content_checksum_set = True

        # then did_field_size
        if ord(buf) & 3 == 0:
            did_field_size = 0
        elif ord(buf) & 3 == 1:
            did_field_size = 1
        elif ord(buf) & 3 == 2:
            did_field_size = 2
        elif ord(buf) & 3 == 3:
            did_field_size = 4

        # check to see if the window descriptor is present
        if not is_single_segment:
            buf = self.infile.read(1)
            check_condition(len(buf) == 1, "not enough data for window descriptor")

        # then read the dictionary
        if did_field_size != 0:
            buf = self.infile.read(did_field_size)
            check_condition(len(buf) == did_field_size, "not enough data for dictionary")

        if fcs_field_size != 0:
            buf = self.infile.read(fcs_field_size)
            check_condition(len(buf) == fcs_field_size,
                            "not enough data for frame content size")
            uncompressed_size = int.from_bytes(buf, byteorder='little')

        # then the blocks: each block starts with 3 bytes
        while True:
            lastblock = False
            buf = self.infile.read(3)
            check_condition(len(buf) == 3, "not enough data for frame")

            # first check if it is the last block
            if buf[0] & 1 == 1:
                lastblock = True

            blocksize = int.from_bytes(buf, byteorder='little') >> 3
            blocktype = int.from_bytes(buf, byteorder='little') >> 1 & 0b11

            # RLE blocks are always size 1, as block size means
            # something else in that context.
            if blocktype == 1:
                blocksize = 1

            check_condition(self.infile.tell() + blocksize <= self.infile.size,
                            "not enough data for frame")

            self.infile.seek(blocksize, os.SEEK_CUR)
            if lastblock:
                break

        if content_checksum_set:
            # lower 32 bytes of xxHash checksum of the original
            # decompressed data
            buf = self.infile.read(4)
            check_condition(len(buf) == 4, "not enough data for checksum")

        self.unpacked_size = self.infile.tell()

        # test integrity
        self.infile.seek(0)
        try:
            reader = zstandard.ZstdDecompressor().stream_reader(self.infile.read(self.unpacked_size))
            payload = reader.read()
        except Exception as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.zst':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_zstd")
        else:
            file_path = pathlib.Path("unpacked_from_zstd")

        # overwrite in case another name was given
        propagated_info = self.from_md.info.get('propagated', {})
        if 'name' in propagated_info:
            file_path = pathlib.Path(propagated_info['name'])

        # search to the start of the file
        self.infile.seek(0)

        # read the compressed data and decompress
        reader = zstandard.ZstdDecompressor().stream_reader(self.infile.read(self.unpacked_size))

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(reader.read())
            yield unpacked_md

    labels = ['zstd', 'compressed']
    metadata = {}
