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

import lz4
import lz4.frame
import xxhash

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import lz4 as kaitai_lz4


class Lz4UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x04\x22\x4d\x18')
    ]
    pretty_name = 'lz4'

    def parse(self):
        try:
            self.data = kaitai_lz4.Lz4.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        for block in self.data.blocks:
            if block.is_endmark:
                break
            if self.data.frame_descriptor.flag.block_checksum:
                block_checksum = xxhash.xxh32(block.data)
                check_condition(block.checksum == block_checksum.intdigest(),
                                "invalid block checksum")

        self.unpacked_size = self.infile.tell()

        # test if descmpression works
        # first create a decompressor object
        decompressor = lz4.frame.create_decompression_context()

        # seek to the input of the input
        self.infile.seek(0)

        bytes_to_read = self.unpacked_size
        readsize = min(bytes_to_read, 1000000)
        unpacking_failed = False

        while True:
            checkbytes = self.infile.read(readsize)
            try:
                uncompressresults = lz4.frame.decompress_chunk(decompressor, checkbytes)
            except Exception as e:
                raise UnpackParserException(e.args)
            bytes_to_read -= readsize
            readsize = min(bytes_to_read, 1000000)
            if readsize == 0:
                break

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.lz4':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_lz4")
        else:
            file_path = pathlib.Path("unpacked_from_lz4")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # first create a decompressor object
            decompressor = lz4.frame.create_decompression_context()

            # seek to the input of the input
            self.infile.seek(0)

            bytes_to_read = self.unpacked_size
            readsize = min(bytes_to_read, 1000000)

            while True:
                checkbytes = self.infile.read(readsize)
                uncompressresults = lz4.frame.decompress_chunk(decompressor, checkbytes)
                outfile.write(uncompressresults[0])
                bytes_to_read -= readsize
                readsize = min(bytes_to_read, 1000000)
                if readsize == 0:
                    break

            yield unpacked_md

    labels = ['compressed', 'lz4']
    metadata = {}
