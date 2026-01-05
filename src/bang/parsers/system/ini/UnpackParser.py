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

import configparser

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException


class IniUnpackParser(UnpackParser):
    extensions = ['.ini']
    signatures = [
    ]
    pretty_name = 'ini'

    def parse(self):
        ini_config = configparser.ConfigParser()

        # open the file again, but then in text mode
        try:
            with open(self.infile.name, 'r') as ini_file:
                ini_config.read_file(ini_file)
        except Exception as e:
            raise UnpackParserException(e.args) from e

    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.size

    labels = ['ini']
    metadata = {}
