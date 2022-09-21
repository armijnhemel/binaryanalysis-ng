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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import icns


class AppleIconUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'icns')
    ]
    pretty_name = 'apple_icon'
    # https://en.wikipedia.org/wiki/Apple_Icon_Image_format

    def parse(self):
        try:
            self.data = icns.Icns.from_io(self.infile)

            # force read data to trigger validations
            parsed = self.data.root_element.data_parsed
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    labels = ['apple', 'apple icon', 'graphics', 'resource']
    metadata = {}
