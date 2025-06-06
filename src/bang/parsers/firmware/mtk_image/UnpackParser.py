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
from . import mtk_image


class AndroidMediatekUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x88\x16\x88\x58')
    ]
    pretty_name = 'mtk_image'

    def parse(self):
        try:
            self.data = mtk_image.MtkImage.from_io(self.infile)

            # force evaluation by kaitai struct for logo structures
            if self.data.header.magic in ['logo', 'LOGO']:
                for img in self.data.payload.data:
                    pass
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        unpacked_files = []

        if self.data.header.magic in ['logo', 'LOGO']:
            # write the raw data. These files are (apparently) in
            # BGRA format which can be converted to regular images.
            # Information necessary for the conversion (such as dimensions)
            # have to be guessed and are not stored anywhere in the file.
            img_counter = 1
            for img in self.data.payload.data:
                file_path = pathlib.Path(f'logo_{img_counter}')

                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(img.body)
                    yield unpacked_md

                img_counter += 1
        else:
            if self.data.header.magic == '':
                file_path = pathlib.Path("unpacked_from_mtk_image")
            else:
                file_path = pathlib.Path(self.data.header.magic)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.payload)
                yield unpacked_md

    @property
    def labels(self):
        labels = ['archive', 'mediatek']
        if self.data.header.magic in ['logo', 'LOGO']:
            labels.append('mediatek logo')
        return labels

    metadata = {}
