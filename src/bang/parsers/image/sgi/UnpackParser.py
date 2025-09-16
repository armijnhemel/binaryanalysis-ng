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
            raise UnpackParserException(e.args) from e

        if self.unpacked_size == self.infile.size:
            # now load the file using PIL as an extra sanity check
            # although this doesn't seem to do a lot.
            try:
                testimg = PIL.Image.open(self.infile)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args) from e
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
                raise UnpackParserException(e.args) from e
            except PIL.Image.DecompressionBombError as e:
                raise UnpackParserException(e.args) from e

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['graphics', 'sgi']

    @property
    def metadata(self):
        metadata = {}
        if self.data.header.name not in ['', 'no name']:
            metadata['name'] = self.data.header.name
        return metadata
