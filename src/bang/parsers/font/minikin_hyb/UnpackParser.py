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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import minikin_hyb


class MinikinHybUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x68\x79\xad\x62')
    ]
    pretty_name = 'minikin_hyb'

    def parse(self):
        file_size = self.infile.size
        try:
            self.data = minikin_hyb.MinikinHyb.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        check_condition(self.data.file_size <= file_size, "invalid file size")
        check_condition(self.data.ofs_alphabet + 4 + self.data.alphabet.alphabet_table.size <= self.data.file_size,
                        "alphabet cannot be outside of file")
        check_condition(self.data.ofs_trie + self.data.trie.size <= self.data.file_size,
                        "trie cannot be outside of file")
        check_condition(self.data.ofs_pattern + self.data.pattern.size <= self.data.file_size,
                        "pattern cannot be outside of file")

    ## make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.file_size

    labels = ['android', 'resource', 'minikin']
    metadata = {}
