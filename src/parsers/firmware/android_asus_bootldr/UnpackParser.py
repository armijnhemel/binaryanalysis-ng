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

'''
Extract bootloader files as found on Qualcomm Snapdragon (MSM)
based Android devices.
'''

import os
import pathlib
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import android_asus_bootldr


class AndroidAsusBootUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BOOTLDR!')
    ]
    pretty_name = 'androidasusboot'

    def parse(self):
        try:
            self.data = android_asus_bootldr.AndroidAsusBootldr.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)


    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        magic_to_files = {'IFWI!!!!': 'ifwi.bin',
                          'DROIDBT!': 'droidboot.img',
                          'SPLASHS!': 'splashscreen.img'}
        unpacked_files = []
        for image in self.data.images:
            if image.magic in magic_to_files:
                file_path = pathlib.Path(magic_to_files[image.magic])
                outfile_rel = self.rel_unpack_dir / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(image.body)
                outfile.close()
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'bootloader']
        metadata = {}

        metadata['vendor'] = 'asus'

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
