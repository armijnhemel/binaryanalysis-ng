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
