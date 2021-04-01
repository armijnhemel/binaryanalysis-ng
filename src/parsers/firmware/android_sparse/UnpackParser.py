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

'''
The Android sparse format is documented in the Android source code tree:

https://android.googlesource.com/platform/system/core/+/master/libsparse/sparse_format.h

Tool to create images with for testing:

* https://android.googlesource.com/platform/system/core/+/master/libsparse - img2simg.c

Note: this is different to the Android sparse data image format.
'''

import os
import pathlib
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import android_sparse

class AndroidSparseUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3a\xff\x26\xed')
    ]
    pretty_name = 'androidsparse'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_sparse(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        self.file_size = self.fileresult.filename.stat().st_size
        try:
            self.data = android_sparse.AndroidSparse.from_io(self.infile)
            self.unpacked_size = self.data.img_header.file_header_size
            for entry in self.data.img_header_entries:
                check_condition(entry.header.chunk_type in android_sparse.AndroidSparse.ChunkTypes,
                                "invalid chunk type")
                if entry.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.raw:
                    check_condition(entry.header.chunk_size * self.data.img_header.block_size == len(entry.body),
                                    "not enough data in body")
                elif entry.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.fill:
                    check_condition(len(entry.body) == 4, "wrong body length")
                elif entry.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.dont_care:
                    check_condition(len(entry.body) == 0, "wrong body length")
                self.unpacked_size += entry.header.total_size
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.file_size >= self.unpacked_size, "not enough data")
        check_condition(self.data.img_header.version.major == 1, "unsupported major version")
        check_condition(self.data.img_header.block_size % 4 == 0, "unsupported block size")

    def unpack(self):
        # there is only one file that needs to be unpacked/created
        unpacked_files = []

        # this is a temporary name. In case there is an ext2/3/4
        # file system (a typical use case on Android) it might be
        # that there is a volume name embedded in the file.
        file_path = "sparse.out"
        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        for entry in self.data.img_header_entries:
            if entry.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.raw:
                outfile.write(entry.body)
            elif entry.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.fill:
                # Fill data, always length 4
                for c in range(0, entry.header.chunk_size):
                    # It has already been checked that blk_sz
                    # is divisible by 4.
                   outfile.write(entry.body*(self.data.img_header.block_size//4))
            elif entry.header.chunk_type == android_sparse.AndroidSparse.ChunkTypes.dont_care:
                for c in range(0, entry.header.chunk_size):
                   outfile.write(b'\x00' * self.data.img_header.block_size)
        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
        unpacked_files.append(fr)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'androidsparse']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
