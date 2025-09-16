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

import pathlib
import zlib
import lzo

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args) from e

        # version, has to be 0x00, 0x10 or 0x20 according
        # to /usr/share/magic and 0x30 and 0x40 according
        # to files observed in the wild and lzop source code
        check_condition(self.data.lzop_version in [0x00, 0x10, 0x20, 0x30, 0x40],
                        "unsupported version")
        for block in self.data.blocks:
            # TODO: checksum verification
            if isinstance(block.block_type, lzop.Lzop.Terminator):
                break

    def unpack(self, meta_directory):
        if self.data.name != '':
            file_path = pathlib.Path(self.data.name)
        else:
            file_path = pathlib.Path('unpacked_from_lzo')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
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
            yield unpacked_md

    labels = ['lzo', 'compressed']
    metadata = {}
