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

import base64
import binascii
import os
import pathlib
import sys

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class DataUriUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'data:image/gif;base64,'),
        (0, b'data:image/jpeg;base64,'),
        (0, b'data:image/webp;base64,'),
        (0, b'data:image/png;base64,'),
        (0, b'data:image/x-png;base64,'),
        (0, b'data:image/svg+xml;base64,'),
        (0, b'data:application/font-woff;base64,'),
        (0, b'data:application/font-woff;charset=utf-8;base64,'),
        (0, b'data:application/x-font-ttf;charset=utf-8;base64,'),
        (0, b'data:application/json;base64,'),
        (0, b'data:application/json;charset=utf-8;base64,'),
        (0, b'data:application/octet-stream;base64,'),
        (0, b'data:application/pdf;base64,'),
        #(0, b'sourceMappingURL=data:application/json;charset=utf-8;base64,'),
    ]
    pretty_name = 'data_uri'

    valid_base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r')
    valid_eob = [b'"', b'\'', b')', b' ']

    def parse(self):
        bytes_read = 0

        max_len_signature = max([len(x[1]) for x in self.signatures])
        header = self.infile.peek(max_len_signature)[:max_len_signature]
        if b'image/gif' in header:
            self.filetype = 'gif'
            seek_offset = 22
        elif b'image/jpeg' in header:
            self.filetype = 'jpg'
            seek_offset = 23
        elif b'image/webp' in header:
            self.filetype = 'webp'
            seek_offset = 23
        elif b'image/png' in header:
            self.filetype = 'png'
            seek_offset = 22
        elif b'image/x-png' in header:
            self.filetype = 'png'
            seek_offset = 24
        elif b'image/svg+xml' in header:
            self.filetype = 'svg'
            seek_offset = 26
        elif b'data:application/font-woff;charset=utf-8;base64,' in header:
            self.filetype = 'woff'
            seek_offset = 48
        elif b'application/font-woff' in header:
            self.filetype = 'woff'
            seek_offset = 34
        elif b'application/x-font-ttf;charset=utf-8' in header:
            self.filetype = 'ttf'
            seek_offset = 49
        elif b'sourceMappingURL=data:application/json;charset=utf-8;base64,' in header:
            self.filetype = 'sourcemap.json'
            seek_offset = 60
        elif b'application/json;charset=utf-8' in header:
            self.filetype = 'json'
            seek_offset = 43
        elif b'application/json' in header:
            self.filetype = 'json'
            seek_offset = 29
        elif b'application/octet-stream' in header:
            self.filetype = 'octet-stream'
            seek_offset = 37
        elif b'application/pdf' in header:
            self.filetype = 'pdf'
            seek_offset = 28

        self.infile.seek(seek_offset, os.SEEK_CUR)
        bytes_read += seek_offset

        block_size = 16384
        self.payload_data = b''
        seen_eob = False

        # check the data, verify that the data is valid base64 data
        while True:
            data = self.infile.read(block_size)
            if data == b'':
                raise UnpackParserException("end of file reached")

            max_eob = sys.maxsize
            for e in self.valid_eob:
                ofs = data.find(e)
                if ofs == -1:
                    continue
                seen_eob = True
                if ofs < max_eob:
                    max_eob = min(max_eob, data.find(e))
                    eob = e

            if seen_eob:
                check_data = data.split(eob, 1)[0]
            else:
                check_data = data

            for i in check_data:
                if chr(i) not in self.valid_base64_chars:
                    raise UnpackParserException("invalid base64")

            self.payload_data += check_data
            bytes_read += len(check_data)

            if seen_eob:
                if len(self.payload_data) == 0:
                    raise UnpackParserException("no uri data for base64")
                try:
                    self.decoded_data = base64.standard_b64decode(self.payload_data)
                except binascii.Error as e:
                    raise UnpackParserException(e.args)
                break
        self.unpacked_size = bytes_read

    def unpack(self, meta_directory):
        unpacked_files = []
        out_labels = []

        file_path = pathlib.Path("unpacked.%s" % self.filetype)

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.decoded_data)
            yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['data uri']
    metadata = {}
