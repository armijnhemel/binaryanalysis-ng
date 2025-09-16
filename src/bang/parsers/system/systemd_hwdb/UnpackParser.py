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

import collections

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import systemd_hwdb


class SystemdHwdbUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'KSLPHHRH')
    ]
    pretty_name = 'systemd_hwdb'

    def parse(self):
        try:
            self.data = systemd_hwdb.SystemdHwdb.from_io(self.infile)

            # recursively walk the tree and read the data to force
            # kaitai struct to evaluate
            node_deque = collections.deque()
            node_deque.append(self.data.root_node)

            while True:
                try:
                    next_node = node_deque.popleft()
                    for c in next_node.children_entries:
                        node_deque.append(c.child)
                    for v in next_node.value_entries:
                        key = v.key
                        value = v.value
                        if self.data.is_value_entry_v2:
                            filename = v.filename
                except IndexError:
                    break

        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    labels = ['systemd', 'resource']
    metadata = {}
