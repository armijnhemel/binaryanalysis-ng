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
from . import pif


class PifUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PIF\x00')
    ]
    pretty_name = 'pif'

    def parse(self):
        try:
            self.data = pif.Pif.from_io(self.infile)

            # read the instance to force evaluation
            img = self.data.image_data
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.file_header.ofs_image_data + self.data.info_header.len_image_data

    labels = ['pif', 'graphics']

    @property
    def metadata(self):
        return { 'width': self.data.info_header.width,
                'height': self.data.info_header.height,
            }
