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

# https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md

import os
import pathlib
import zstandard

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class ZstdUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x28\xb5\x2f\xfd')
    ]
    pretty_name = 'zstd'

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

            check_condition(self.infile.tell() + blocksize <= self.fileresult.filesize,
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
            raise UnpackParserException(e.args)

    def unpack(self):
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.zst':
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_zstd")
        else:
            file_path = pathlib.Path("unpacked_from_zstd")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        self.infile.seek(0)

        reader = zstandard.ZstdDecompressor().stream_reader(self.infile.read(self.unpacked_size))
        outfile.write(reader.read())
        outfile.close()

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
        unpacked_files.append(fr)

        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['zstd', 'compressed']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
