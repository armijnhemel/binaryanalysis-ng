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
from . import dfu


class DfuUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DfuSe')
    ]
    pretty_name = 'dfu'

    def parse(self):
        try:
            self.data = dfu.Dfu.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        target_counter = 1
        for target in self.data.targets:
            out_labels = []
            if target.name == '':
                target_name = pathlib.Path("unpacked-from-dfu-%d" % target_counter)
            else:
                target_name = pathlib.Path(target.name)

            with meta_directory.unpack_regular_file(target_name) as (unpacked_md, outfile):
                for elem in target.elements:
                    outfile.write(elem.data)

                yield unpacked_md
            target_counter += 1

    labels = ['dfu', 'firmware']

    @property
    def metadata(self):
        metadata = {
            'hardware' : {
                'product_id': self.data.product,
                'vendor_id': self.data.vendor
            }
        }
        return metadata
