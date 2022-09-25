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

import io
import os
import pathlib
import zipfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import crx


class CrxUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'Cr24')
    ]
    pretty_name = 'crx'

    def parse(self):
        try:
            self.data = crx.Crx.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        zip_offset = self.data.header.len_header
        zip_end = self.infile.tell()

        # seek to the start of the ZIP file
        self.infile.seek(zip_offset)

        # read the data
        zip_data = io.BytesIO(self.infile.read(zip_end - zip_offset))
        try:
            crx_zip = zipfile.ZipFile(zip_data)
        except:
            pass
        for z in crx_zip.infolist():
            file_path = pathlib.Path(z.filename)
            try:
                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(crx_zip.read(z))
                    yield unpacked_md
            except Exception as e:
                pass

    labels = ['crx', 'chrome']
    metadata = {}
