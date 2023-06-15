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

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import xiaomi_firmware


class XiaomiFirmwareUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'HDR1'),
        (0, b'HDR2')
    ]
    pretty_name = 'xiaomi_firmware'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = xiaomi_firmware.XiaomiFirmware.from_io(self.infile)

            # ugly hack to read all the data
            for blob in self.data.header.ofs_blobs:
                if blob.ofs_blob == 0:
                    continue
                self.unpacked_size = max(self.unpacked_size, blob.ofs_blob + 48 + blob.blob.len_data)

            # signature
            self.unpacked_size = max(self.unpacked_size, self.data.header.ofs_signature + 16 + self.data.header.signature.len_signature)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        for blob in self.data.header.ofs_blobs:
            if blob.ofs_blob == 0:
                continue
            if blob.blob.name == '':
                continue
            file_path = pathlib.Path(blob.blob.name)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(blob.blob.data)
                yield unpacked_md

    labels = ['xiaomi', 'firmware']
    metadata = {}
