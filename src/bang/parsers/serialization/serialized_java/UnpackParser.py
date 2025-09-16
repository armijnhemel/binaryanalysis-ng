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

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import serialized_java


class SerializedJavaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xac\xed\x00\x05')
    ]
    pretty_name = 'serialized_java'

    def parse(self):
        try:
            self.data = serialized_java.SerializedJava.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        self.unpacked_size = 4
        for block in self.data.blocks:
            if block.is_valid:
                if block.symbol == serialized_java.SerializedJava.Symbols.block_data_long:
                    self.unpacked_size += 1 + 4 + block.body.len_data
                else:
                    self.unpacked_size += 1 + 1 + block.body.len_data

    def calculate_unpacked_size(self):
        pass

    labels = ['serialized java']
    metadata = {}
