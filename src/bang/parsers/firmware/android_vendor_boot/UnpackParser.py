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

import os
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_vendor_boot


class AndroidVendorBootUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'VNDRBOOT')
    ]
    pretty_name = 'android_vendor_boot'

    def parse(self):
        try:
            self.data = android_vendor_boot.AndroidVendorBoot.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        if self.data.header.version == 3:
            file_path = pathlib.Path('vendor_ramdisk')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.vendor_ramdisk.data)
                yield unpacked_md
        elif self.data.header.version == 4:
            ramdisk_counter = 1
            for ramdisk in self.data.vendor_ramdisk_table.entries:
                if ramdisk.name == '':
                    file_path = pathlib.Path("ramdisk-%d" % ramdisk_counter)
                else:
                    file_path = pathlib.Path(ramdisk.name)
                ramdisk_counter += 1

                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(ramdisk.ramdisk)
                    yield unpacked_md

        file_path = pathlib.Path('dtb')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.dtb)
            yield unpacked_md

    labels = ['android vendor boot', 'android']

    @property
    def metadata(self):
        # store the commandline options in an easier to search dict
        commandline_options = {}
        '''
        for c in self.data.header.commandline.split():
            cmd, value = c.split('=', maxsplit=1)

            # there can be multiple instances of the same option,
            # but the Linux kernel will use the one specified last
            # so it is safe to simply not check for duplicates.
            commandline_options[cmd] = value
        '''

        metadata = {
            'commandline': self.data.header.commandline,
            'version': self.data.header.version,
            'commandline_options': commandline_options
        }
        return metadata
