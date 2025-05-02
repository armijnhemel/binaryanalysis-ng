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
from . import nibarchive


class NibArchiveUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'NIBArchive'),
    ]
    pretty_name = 'nibarchive'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = nibarchive.Nibarchive.from_io(self.infile)

            # force read data as these are properties
            # TODO: extra sanity checks
            num_keys = len(self.data.keys)
            self.unpacked_size = max(self.unpacked_size, self.data._debug['_m_keys']['end'])

            num_values = len(self.data.values)
            self.unpacked_size = max(self.unpacked_size, self.data._debug['_m_values']['end'])

            num_class_names = len(self.data.class_names)
            self.unpacked_size = max(self.unpacked_size, self.data._debug['_m_class_names']['end'])
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        pass

    labels = ['nibarchive', 'resource']
    metadata = {}
