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

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import fpkg


class FpkgUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FPKG')
    ]
    pretty_name = 'fpkg'

    def parse(self):
        # parse the file, possibly this will fail when carving because _io.size
        # and _io.pos are used in the Kaitai Struct definition (because of 'repeat: eos')
        # which uses the regular file and not the OffsetInputFile
        try:
            self.data = fpkg.Fpkg.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        for file in self.data.files:
            file_path = pathlib.Path(file.rest_of_header.name)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(file.data)
                yield unpacked_md

    labels = ['fpkg', 'firmware']
    metadata = {}
