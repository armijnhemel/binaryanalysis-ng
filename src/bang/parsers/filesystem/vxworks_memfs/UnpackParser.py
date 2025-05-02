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

import lzma
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
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
            raise UnpackParserException(e.args)

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
