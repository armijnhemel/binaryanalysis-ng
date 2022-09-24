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

import PIL.Image

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import sgi


class SgiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x01\xda')
    ]
    pretty_name = 'sgi'

    def parse(self):
        try:
            self.unpacked_size = 0
            self.data = sgi.Sgi.from_io(self.infile)
            if self.data.header.storage_format == sgi.Sgi.StorageFormat.rle:
                for i in range(0, len(self.data.body.start_table_entries)):
                    self.unpacked_size = max(self.unpacked_size, self.data.body.start_table_entries[i] + self.data.body.length_table_entries[i])
                for scanline in self.data.body.scanlines:
                    # read data because Kaitai Struct evaluates instances lazily
                    len_data = len(scanline.data)
                check_condition(self.unpacked_size <= self.infile.size,
                            "data cannot be outside of file")
            else:
                self.unpacked_size = self.infile.tell()
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        if self.unpacked_size == self.infile.size:
            # now load the file using PIL as an extra sanity check
            # although this doesn't seem to do a lot.
            try:
                testimg = PIL.Image.open(self.infile)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
        else:
            # load the SGI data into memory
            self.infile.seek(0)
            sgi_bytes = io.BytesIO(self.infile.read(self.unpacked_size))

            # test in PIL
            try:
                testimg = PIL.Image.open(sgi_bytes)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
            except PIL.Image.DecompressionBombError as e:
                raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['graphics', 'sgi']

    @property
    def metadata(self):
        metadata = {}
        if self.data.header.name != '' and self.data.header.name != 'no name':
            metadata['name'] = self.data.header.name
        return metadata
