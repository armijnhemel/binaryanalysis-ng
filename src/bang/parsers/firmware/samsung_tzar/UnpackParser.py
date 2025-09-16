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
from . import samsung_tzar


# test file: https://github.com/HenriDellal/kernel-samsung-a105f/blob/master/drivers/misc/tzdev/3.0/startup.tzar
class SamsungTzarUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x7f\xa5\x54\x41') # is this correct???
    ]
    pretty_name = 'samsung_tzar'

    def parse(self):
        try:
            self.data = samsung_tzar.SamsungTzar.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        for entry in self.data.entries.entries:
            file_path = pathlib.Path(entry.filename)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.data)
                yield unpacked_md

    labels = ['samsung', 'samsung tzar']
    metadata = {}
