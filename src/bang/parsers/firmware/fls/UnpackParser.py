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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import fls


class FlsUnpackParser(UnpackParser):
    extensions = ['.fls']
    signatures = []
    pretty_name = 'fls'

    def parse(self):
        try:
            self.data = fls.Fls.from_io(self.infile)
            for entry in self.data.entries:
                if entry.len_data == 0:
                    continue
                check_condition(entry.ofs_data + entry.len_data <= self.data.header.len_file,
                                "invalid offset or data length")
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        for entry in self.data.entries:
            if entry.len_data == 0:
                continue

            if entry.name == '':
                continue

            file_path = pathlib.Path(entry.name)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.data)
                yield unpacked_md

    labels = ['fls', 'firmware']

    @property
    def metadata(self):
        metadata = {'files': len(self.data.entries)}
        return metadata
