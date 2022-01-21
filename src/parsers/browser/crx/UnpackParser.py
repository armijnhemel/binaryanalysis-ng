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
import zipfile

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    def unpack(self):
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

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
            try:
                crx_zip.extract(z, unpackdir_full)
                fr = FileResult(self.fileresult, self.rel_unpack_dir / z.filename, set())
                unpacked_files.append(fr)
            except Exception as e:
                pass

        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['crx', 'chrome']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
