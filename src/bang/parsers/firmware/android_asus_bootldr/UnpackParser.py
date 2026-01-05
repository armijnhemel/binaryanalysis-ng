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

'''
Extract bootloader files as found on some Android devices made by ASUS.
'''

import pathlib

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_bootldr_asus


class AndroidAsusBootUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BOOTLDR!')
    ]
    pretty_name = 'androidasusboot'

    def parse(self):
        try:
            self.data = android_bootldr_asus.AndroidBootldrAsus.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        chunk_to_files = {'IFWI!!!!': 'ifwi.bin',
                          'DROIDBT!': 'droidboot.img',
                          'SPLASHS!': 'splashscreen.img'}
        for image in self.data.images:
            if image.file_name != '':
                file_path = pathlib.Path(image.file_name)
            else:
                file_path = pathlib.Path(chunk_to_files[image.chunk_id])
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(image.body)
                yield unpacked_md

    labels = ['android', 'bootloader']
    metadata = { 'vendor': 'asus' }
