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
from . import minifs


class MinifsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MINIFS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    ]
    pretty_name = 'minifs'

    def parse(self):
        try:
            self.data = minifs.Minifs.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # test decompress all LZMA blobs
        for blob in self.data.lzma_blobs:
            try:
                lzma.decompress(blob.data)
            except lzma.LZMAError as e:
                raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        cached_lzma = b''
        last_blob = 0
        for entry in self.data.inodes:
            file_path = pathlib.Path(entry.directory_name) / entry.filename

            # decompress the LZMA blob, unless it has been cached
            if cached_lzma == b'' or entry.lzma_blob != last_blob:
                cached_lzma = lzma.decompress(self.data.lzma_blobs[entry.lzma_blob].data)
                last_blob = entry.lzma_blob
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(cached_lzma[entry.ofs_file:entry.ofs_file + entry.size])
                yield unpacked_md

    labels = ['tp-link', 'filesystem', 'minifs']
    metadata = {}
