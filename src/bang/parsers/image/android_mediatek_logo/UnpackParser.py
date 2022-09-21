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
from . import android_mediatek_logo


class AndroidMediatekUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x88\x16\x88\x58')
    ]
    pretty_name = 'android_mediatek_logo'

    def parse(self):
        try:
            self.data = android_mediatek_logo.AndroidMediatekLogo.from_io(self.infile)

            # force evaluation by kaitai struct
            for img in self.data.payload.data:
                pass
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        unpacked_files = []

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

    labels = ['graphics', 'android', 'mediatek logo']
    metadata = {}
