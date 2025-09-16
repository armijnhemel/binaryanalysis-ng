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

import pathlib

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import seama


class SeamaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5e\xa3\xa4\x17')
    ]
    pretty_name = 'seama'

    def parse(self):
        try:
            self.data = seama.Seama.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        file_path = pathlib.Path('image')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.image)
            yield unpacked_md

    labels = ['seama']

    @property
    def metadata(self):
        """sets metadata and labels for the unpackresults"""
        metadata = {}
        metadata_strings = []
        try:
            metas = self.data.metadata.split(b'\x00')
            for i in metas:
                meta_string = i.decode()
                if meta_string != '':
                    metadata_strings.append(meta_string)
        except:
            pass
        if metadata_strings:
            metadata['metadata'] = metadata_strings
        return metadata
