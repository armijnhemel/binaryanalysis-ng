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

# LOD is a text based firmware file format for certain RDA and
# Coolsand chipsets used in mobile phones.

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class LodUnpackParser(UnpackParser):
    extensions = []
    signatures = [(0, b'#$mode=flsh_spi32m')
    ]
    pretty_name = 'lod'

    def parse(self):
        unpacked = 0

        try:
            # open the file again, but then in text mode
            lod_file = open(self.infile.name, 'r', newline='')
        except:
            raise UnpackParserException("Cannot decode file as text")

        # read the lines of the data, until either EOF
        # or until the end of the lod data has been reached
        data_unpacked = False

        try:
            for line in lod_file:
                if line.startswith('#'):
                    # comments
                    unpacked += len(line)
                    continue

                if line.startswith('@'):
                    # memory address
                    unpacked += len(line)
                    continue

                bytes.fromhex(line.rstrip())

                unpacked += len(line)
        except (UnicodeDecodeError, ValueError) as e:
            lod_file.close()
            raise UnpackParserException("cannot decode")

        lod_file.close()

        # TODO: sanity checks for record types
        check_condition(unpacked != 0, "no data unpacked")

        self.unpacked_size = unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        file_path = pathlib.Path("unpacked_from_lod")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            lod_file = open(self.infile.name, 'r')

            for lod_line in lod_file:
                line = lod_line.rstrip()

                if line.startswith('#'):
                    # comments
                    continue
                if line.startswith('@'):
                    # memory address
                    continue

                # the data is byte swapped, so first reverse
                outfile.write(bytes(reversed(bytes.fromhex(line))))

            lod_file.close()
            yield unpacked_md

    labels = ['lod']
    metadata = {}
