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
from . import zcomax


# http://web.archive.org/web/20210620033751/https://www.zcomax.com/zcn-1523h-2-8
# ZCN-1523H-X-DR.zip
class ZcomaxUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x66\x69\x72\x6d')
    ]
    pretty_name = 'zcomax'

    def parse(self):
        try:
            self.data = zcomax.Zcomax.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        out_labels = []

        file_path = pathlib.Path('kernel')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.firmware_body.kernel.body)
            yield unpacked_md

        file_path = pathlib.Path('rootfs')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.firmware_body.rootfs.body)
            yield unpacked_md

    labels = ['zcomax']
    metadata = {}
