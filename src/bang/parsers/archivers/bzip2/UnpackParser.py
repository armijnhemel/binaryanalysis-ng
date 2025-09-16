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

import bz2
import pathlib

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import bzip2


class Bzip2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BZh01AY&SY'),
        (0, b'BZh11AY&SY'),
        (0, b'BZh21AY&SY'),
        (0, b'BZh31AY&SY'),
        (0, b'BZh41AY&SY'),
        (0, b'BZh51AY&SY'),
        (0, b'BZh61AY&SY'),
        (0, b'BZh71AY&SY'),
        (0, b'BZh81AY&SY'),
        (0, b'BZh91AY&SY')
    ]
    pretty_name = 'bzip2'

    def parse(self):
        try:
            self.data = bzip2.Bzip2.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        # the header parsed cleanly, so test unpack the data
        # First reset the offset
        self.infile.seek(0)

        # then create a bzip2 decompressor
        bz2decompressor = bz2.BZ2Decompressor()

        # incrementally read compressed data and decompress:
        # https://docs.python.org/3/library/bz2.html#incremental-de-compression

        self.unpacked_size = 0
        datareadsize = 10000000
        bz2data = self.infile.read(datareadsize)
        while bz2data != b'':
            try:
                bz2decompressor.decompress(bz2data)
            except EOFError:
                break
            except Exception as e:
                raise UnpackParserException(e.args) from e

            # there is no more compressed data
            self.unpacked_size += len(bz2data) - len(bz2decompressor.unused_data)
            if bz2decompressor.unused_data != b'':
                break
            bz2data = self.infile.read(datareadsize)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.bz2':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_bz2")
        elif meta_directory.file_path.suffix.lower() in ['.tbz', '.tbz2', '.tb2', '.tarbz2']:
            file_path = pathlib.Path(meta_directory.file_path.stem + ".tar")
        else:
            file_path = pathlib.Path("unpacked_from_bz2")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # First reset the offset
            self.infile.seek(0)

            # then create a bzip2 decompressor
            bz2decompressor = bz2.BZ2Decompressor()

            # incrementally read compressed data and decompress:
            # https://docs.python.org/3/library/bz2.html#incremental-de-compression
            datareadsize = 10000000
            bz2data = self.infile.read(datareadsize)
            while bz2data != b'':
                try:
                    unpacked_data = bz2decompressor.decompress(bz2data)
                    outfile.write(unpacked_data)
                except EOFError:
                    break

                # there is no more compressed data
                if bz2decompressor.unused_data != b'':
                    break
                bz2data = self.infile.read(datareadsize)
            yield unpacked_md

    labels = ['bzip2', 'compressed']
    metadata = {}
