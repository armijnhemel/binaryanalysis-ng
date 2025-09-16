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
from . import uf2


class Uf2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'UF2\n')
    ]
    pretty_name = 'uf2'

    def parse(self):
        try:
            self.data = uf2.Uf2.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        check_condition(self.data.uf2_block_start.block_number == 0,
                        'invalid start block')

    def unpack(self, meta_directory):
        # cut .uf2 from the path name if it is there
        if meta_directory.file_path.suffix.lower() == '.uf2':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                # invalid path, so make anonymous
                file_path = pathlib.Path("unpacked_from_uf2")
        else:
            # else anonymous file
            file_path = pathlib.Path("unpacked_from_uf2")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.uf2_block_start.data)
            for uf2_block in self.data.uf2_blocks:
                outfile.write(uf2_block.data)
            yield unpacked_md

    labels = ['uf2', 'firmware']

    @property
    def metadata(self):
        return {
            'platform': self.data.uf2_block_start.family_id.name
        }
