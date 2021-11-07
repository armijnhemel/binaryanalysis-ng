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
The Android A/B update format is either a full image or an update image.
The focus here is first on the full image. The specification cannot be
fully captured in Kaitai Struct as it part of the data structure is done
using Google Protobuf.

This parser uses both Kaitai Struct and a parser generated from the Protobuf
sources. Kaitai Struct is used for the first big sweep and several syntactical
checks. The Protobuf generated parsers is then used to extract the data.
'''

import os
import pathlib
from FileResult import FileResult

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import android_update
from . import google_protobuf
from . import vlq_base128_le


class AndroidUpdateUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'CrAU')
    ]
    pretty_name = 'android_update'

    def parse(self):
        check_condition(1 != 1, "disabled")
        try:
            self.data = android_update.AndroidUpdate.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.img_header.len_image + self.offset <= self.infile.size, "not enough data")

    labels = ['allwinner']
    metadata = {}

