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

'''
The Android sparse format is documented in the Android source code tree:

https://android.googlesource.com/platform/system/core/+/master/libsparse/sparse_format.h

Tool to create images with for testing:

* https://android.googlesource.com/platform/system/core/+/master/libsparse - img2simg.c

Note: this is different to the Android sparse data image format.
'''

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_sparse


class AndroidSparseUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3a\xff\x26\xed')
    ]
    pretty_name = 'androidsparse'

    def parse(self):
        try:
            self.data = android_sparse.AndroidSparse.from_io(self.infile)
            self.unpacked_size = self.data.header.len_header
            for chunk in self.data.chunks:
                check_condition(chunk.header.chunk_type in android_sparse.AndroidSparse.ChunkTypes,
                                "invalid chunk type")
                if chunk.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.raw:
                    check_condition(chunk.header.num_body_blocks * self.data.header.block_size == len(chunk.body),
                                    "not enough data in body")
                elif chunk.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.fill:
                    check_condition(len(chunk.body) == 4, "wrong body length")
                elif chunk.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.dont_care:
                    check_condition(len(chunk.body) == 0, "wrong body length")
                self.unpacked_size += chunk.header.len_chunk
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e
        check_condition(self.infile.size >= self.unpacked_size, "not enough data")
        check_condition(self.data.header.version.major == 1, "unsupported major version")
        check_condition(self.data.header.block_size % 4 == 0, "unsupported block size")

    def unpack(self, meta_directory):
        # there is only one file that needs to be unpacked/created

        # this is a temporary name. In case there is an ext2/3/4
        # file system (a typical use case on Android) it might be
        # that there is a volume name embedded in the file.
        file_path = pathlib.Path("sparse.out")
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            for chunk in self.data.chunks:
                if chunk.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.raw:
                    outfile.write(chunk.body)
                elif chunk.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.fill:
                    # Fill data, always length 4
                    for c in range(0, chunk.header.num_body_blocks):
                        # It has already been checked that blk_sz
                        # is divisible by 4.
                        outfile.write(chunk.body*(self.data.header.block_size//4))
                elif chunk.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.dont_care:
                    for c in range(0, chunk.header.num_body_blocks):
                        outfile.write(b'\x00' * self.data.header.block_size)

            yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['android', 'androidsparse']
    metadata = {}
