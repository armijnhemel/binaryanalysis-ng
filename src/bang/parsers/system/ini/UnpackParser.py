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

import configparser

from bang.UnpackParser import UnpackParser, check_condition
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
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.size

    labels = ['ini']
    metadata = {}
