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

import os
import pathlib
import base64
import binascii
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

class DataUriUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'data:image/gif;base64,'),
        (0, b'data:image/jpeg;base64,'),
        (0, b'data:image/png;base64,'),
    ]
    pretty_name = 'data_uri'

    validbase64chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r')

    def parse(self):
        bytes_read = 0
        header = self.infile.peek(25)
        if b'gif' in header:
            self.filetype = 'gif'
            self.infile.seek(22, os.SEEK_CUR)
            bytes_read += 22
        elif b'jpeg' in header:
            self.filetype = 'jpg'
            self.infile.seek(23, os.SEEK_CUR)
            bytes_read += 23
        elif b'png' in header:
            self.filetype = 'png'
            self.infile.seek(22, os.SEEK_CUR)
            bytes_read += 22

        block_size = 1024
        self.payload_data = b''
        eob = False
        # check the data, verify that the data is valid base64 data
        while True:
            data = self.infile.read(block_size)
            if data == b'':
                raise UnpackParserException("end of file reached")
            # TODO: also valid eob are "'", " " and ")"
            if b'"' in data:
                eob = True
            check_data = data.split(b'"', 1)[0]
            for i in check_data:
                if chr(i) not in self.validbase64chars:
                    raise UnpackParserException("invalid base64")
            self.payload_data += check_data
            bytes_read += len(check_data)
            if eob:
                if len(self.payload_data) == 0:
                    raise UnpackParserException("no uri data for base64")
                try:
                    self.decoded_data = base64.standard_b64decode(self.payload_data)
                except binascii.Error as e:
                    raise UnpackParserException(e.args)
                break
        self.unpacked_size = bytes_read

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        out_labels = []

        file_path = pathlib.Path("unpacked.%s" % self.filetype)

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.decoded_data)
        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['data uri']

        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
