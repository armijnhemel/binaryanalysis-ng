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
import zlib
import lzo

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import lzop


class LzopUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'lzop'

    def parse(self):
        try:
            self.data = lzop.Lzop.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # version, has to be 0x00, 0x10 or 0x20 according
        # to /usr/share/magic and 0x30 and 0x40 according
        # to files observed in the wild and lzop source code
        check_condition(self.data.lzop_version in [0x00, 0x10, 0x20, 0x30, 0x40],
                        "unsupported version")
        for block in self.data.blocks:
            # TODO: checksum verification
            if isinstance(block.block_type, lzop.Lzop.Terminator):
                break


    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        out_labels = []
        if self.data.name != '':
            file_path = pathlib.Path(self.data.name)
        else:
            file_path = 'unpacked-from-lzo'

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        counter = 1
        for block in self.data.blocks:
            if isinstance(block.block_type, lzop.Lzop.Terminator):
                break
            if block.len_decompressed == block.block_type.len_compressed:
                # if the compressed and decompressed length are the same
                # then the data needs to be written directly it seems.
                outfile.write(block.block_type.data)
            else:
                # various methods are allowed according to conf.h in lzop code
                # 1, 2, 3 are LZO related
                # 0x1a, 0x1b, 0x2a, 0x2b, 0x2d are NRV related (discontinued library)
                # 128 is zlib related
                # In practice LZO ones will be used the most
                if self.data.method.value in [1, 2, 3]:
                    # TODO: catch errors
                    magic = b'\xf0' + int.to_bytes(block.len_decompressed, 4, 'big')
                    outfile.write(lzo.decompress(magic + block.block_type.data))
                elif self.data.method.value == 128:
                    # seemingly not used in practice
                    outfile.write(zlib.decompress(block.block_type.data))
            counter += 1
        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['lzo', 'compressed']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
