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
from . import realtek_bootloader

# test files:
# D-Link
# DWR_M921_V1_1_36_upgrade_5e73523d1dffd.bin
#
# Tenda
# '4G09v2.0 Firmware V16.03.07.26.zip'
# non-standard


class RealtekBootloaderUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'cr6c')
    ]
    pretty_name = 'realtek_bootloader'

    def parse(self):
        self.unpacked_size = 0
        self.has_rootfs = False
        try:
            self.data = realtek_bootloader.RealtekBootloader.from_io(self.infile)

            # TODO: checksum
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        # read the next 4 bytes to see if there is a root file system
        pos = self.infile.tell()
        rootfs_bytes = self.infile.peek(4)[:4]
        if rootfs_bytes == b'r6cr':
            try:
                self.rootfs = realtek_bootloader.RealtekBootloader.from_io(self.infile)

                # TODO: checksum
                self.has_rootfs = True
            except (Exception, ValidationFailedError):
                pass

    def unpack(self, meta_directory):
        file_path = pathlib.Path('data')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.data)
            yield unpacked_md
        if self.has_rootfs:
            file_path = pathlib.Path('rootfs')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.rootfs.data)
                yield unpacked_md

    labels = ['realtek_bootloader']
    metadata = {}
