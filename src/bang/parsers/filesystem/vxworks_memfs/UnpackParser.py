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
from . import vxworks_memfs


class VxworksMemfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'owowowowowowowowowowowowowowowow')
    ]
    pretty_name = 'vxworks_memfs'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = vxworks_memfs.VxworksMemfs.from_io(self.infile)

            # force read to evaluate
            for entry in self.data.entries:
                lzma.decompress(entry.data)
                self.unpacked_size = max(self.unpacked_size, entry.ofs_data + entry.len_data)
        except (Exception, ValidationFailedError, lzma.LZMAError) as e:
            raise UnpackParserException(e.args) from e

    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        for entry in self.data.entries:
            file_path = pathlib.Path(entry.name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(lzma.decompress(entry.data))
                yield unpacked_md

    labels = ['vxworks', 'filesystem']
    metadata = {}
