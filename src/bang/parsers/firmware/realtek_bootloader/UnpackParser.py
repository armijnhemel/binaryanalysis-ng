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
from . import realtek_bootloader

# test file:
# '4G09v2.0 Firmware V16.03.07.26.zip'
# Tenda


class RealtekBootloaderUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'cr6c')
    ]
    pretty_name = 'realtek_bootloader'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = realtek_bootloader.RealtekBootloader.from_io(self.infile)

            # TODO: checksum
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        file_path = pathlib.Path('data')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.data)
            yield unpacked_md

    labels = ['realtek_bootloader']
    metadata = {}
