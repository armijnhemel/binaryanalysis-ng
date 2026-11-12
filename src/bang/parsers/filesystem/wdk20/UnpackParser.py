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

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import wdk20


class Wdk20UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (18, b'WDK 2.0\x00')
    ]
    pretty_name = 'wdk20'

    def parse(self):
        try:
            self.data = wdk20.Wdk20.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        # test decompress all LZMA blobs
        for inode in self.data.inodes.inodes:
            if inode.data:
                if inode.unknown != b'\x04':
                    try:
                        lzma.decompress(inode.data)
                    except lzma.LZMAError as e:
                        raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        for inode in self.data.inodes.inodes:
            file_path = pathlib.Path(inode.name)

            # decompress the LZMA blob
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                if inode.data and inode.unknown != b'\x04':
                    outfile.write(lzma.decompress(inode.data))
                else:
                    outfile.write(inode.data)
                yield unpacked_md

    labels = ['filesystem', 'wdk20']
    metadata = {}
