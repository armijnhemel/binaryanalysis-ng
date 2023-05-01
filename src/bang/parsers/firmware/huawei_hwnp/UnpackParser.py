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
from . import hwnp


class HuaweiFirmwareUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'HWNP')
    ]
    pretty_name = 'huawei_firmware'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = hwnp.Hwnp.from_io(self.infile)

            # ugly hack to read all the data
            for item in self.data.products_and_items.items:
                if item.len_data == 0:
                    continue
                self.unpacked_size = max(self.unpacked_size, item.ofs_data + item.len_data)
                check_condition(len(item.data) == item.len_data, "not enough data")
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        for item in self.data.products_and_items.items:
            if item.len_data == 0:
                continue

            if item.name == '':
                continue

            if 'file:/' in item.name:
                file_path = pathlib.Path(item.name.split(':/', maxsplit=1)[1])
            else:
                file_path = pathlib.Path(item.name)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(item.data)
                yield unpacked_md

    labels = ['huawei', 'firmware']
    metadata = {}
