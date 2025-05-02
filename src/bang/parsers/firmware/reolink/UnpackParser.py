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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import reolink
from . import reolink_logo


class ReolinkUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x13\x59\x72\x32')
    ]
    pretty_name = 'reolink'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = reolink.Reolink.from_io(self.infile)

            # ugly hack to read all the data
            for section in self.data.sections:
                if section.len_section == 0:
                    continue
                self.unpacked_size = max(self.unpacked_size, section.ofs_section + section.len_section)
                check_condition(len(section.section) == section.len_section, "not enough data")
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        for section in self.data.sections:
            if section.len_section == 0:
                continue
            if section.name == '':
                continue

            file_path = pathlib.Path(section.name)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(section.section)
                yield unpacked_md

    labels = ['reolink', 'firmware']
    metadata = {}


class ReolinkLogoUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'GLOR')
    ]
    pretty_name = 'reolink_logo'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = reolink_logo.ReolinkLogo.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        file_path = pathlib.Path('1.jpeg')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.jpeg_1)
            yield unpacked_md

        file_path = pathlib.Path('2.jpeg')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.jpeg_2)
            yield unpacked_md

    labels = ['reolink_logo', 'resource']
    metadata = {}
