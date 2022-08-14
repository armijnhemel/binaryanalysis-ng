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

import os
import pathlib

import lz4
import lz4.frame
import xxhash

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.lz4':
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_lz4")
        else:
            file_path = pathlib.Path("unpacked_from_lz4")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        # first create a decompressor object
        decompressor = lz4.frame.create_decompression_context()

        # seek to the input of the input
        self.infile.infile.seek(self.offset)

        bytes_to_read = self.unpacked_size
        readsize = min(bytes_to_read, 1000000)
        unpacking_failed = False

        while True:
            checkbytes = self.infile.read(readsize)
            try:
                uncompressresults = lz4.frame.decompress_chunk(decompressor, checkbytes)
                outfile.write(uncompressresults[0])
                outfile.flush()
            except:
                unpacking_failed = True
                break
            bytes_to_read -= readsize
            readsize = min(bytes_to_read, 1000000)
            if readsize == 0:
                break

        outfile.close()
        if unpacking_failed:
            outfile_full.unlink()
        else:
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
            unpacked_files.append(fr)

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['compressed', 'lz4']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
