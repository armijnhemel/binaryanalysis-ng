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

from bang.UnpackParser import UnpackParser
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
            raise UnpackParserException(e.args) from e

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
