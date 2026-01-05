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
from . import tplink_minifs


class MinifsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MINIFS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    ]
    pretty_name = 'tplink_minifs'

    def parse(self):
        try:
            self.data = tplink_minifs.TplinkMinifs.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        # test decompress all LZMA blobs
        for blob in self.data.lzma_blobs:
            try:
                lzma.decompress(blob.data)
            except lzma.LZMAError as e:
                raise UnpackParserException(e.args) from e

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
