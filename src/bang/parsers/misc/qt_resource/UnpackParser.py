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
from . import qt_resource


class QtResourceUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'qres'),
    ]
    pretty_name = 'qt_resource'

    def parse(self):
        try:
            self.data = qt_resource.QtResource.from_io(self.infile)
            for entry in self.data.name_table.entries:
                name = entry.name.decode('utf-16-be')
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(len(self.data.data_block.entries) == len(self.data.name_table.entries),
                        "amount of names and files do not match")

    def unpack(self, meta_directory):
        counter = 0
        for entry in self.data.data_block.entries:
            file_path = pathlib.Path(self.data.name_table.entries[counter].name.decode('utf-16-be'))

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.data)
                yield unpacked_md

            counter += 1

    labels = ['qt', 'resource']
    metadata = {}
