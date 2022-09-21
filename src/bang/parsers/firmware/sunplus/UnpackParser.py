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

import binascii
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import sunplus


class SunplusUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'SUNP BURN FILE\x00\x00')
    ]
    pretty_name = 'sunplus'

    def parse(self):
        try:
            self.data = sunplus.Sunplus.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        file_path = pathlib.Path('isp_bootloader')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.isp_bootloader)
            yield unpacked_md

        if self.data.len_aimg != 0:
            file_path = pathlib.Path('aimg')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.aimg)
                yield unpacked_md

        # TODO: split this further into two FAT images
        # see https://github.com/Linouth/iCatch-V50-Playground
        if self.data.len_bimg != 0:
            file_path = pathlib.Path('bimg')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.bimg)
                yield unpacked_md

        if self.data.len_cimg != 0:
            file_path = pathlib.Path('cimg')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.cimg)
                yield unpacked_md

        if self.data.len_bin != 0:
            file_path = pathlib.Path('bin')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.bin)
                yield unpacked_md

        if self.data.len_bad_pixel != 0:
            file_path = pathlib.Path('bad_pixel')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.bad_pixel)
                yield unpacked_md

        if self.data.len_dram != 0:
            file_path = pathlib.Path('dram')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.dram)
                yield unpacked_md

    labels = ['sunplus', 'firmware']
    metadata = {}
