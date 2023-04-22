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

import collections

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import systemd_hwdb


class SystemdHwdb(UnpackParser):
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
            raise UnpackParserException(e.args)

    labels = ['systemd', 'resource']
    metadata = {}
