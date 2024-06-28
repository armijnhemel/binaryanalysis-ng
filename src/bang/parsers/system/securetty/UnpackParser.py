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

# verify Unix securetty
# man 5 securetty

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

RE_TTY = re.compile(r'(ttyS?\d+|pts/\d+)$')


class SecureTTYUnpackParser(UnpackParser):
    extensions = ['securetty']
    signatures = [
    ]
    pretty_name = 'securetty'

    def parse(self):
        # open the file again, but then in text mode
        try:
            securetty_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            securetty_file.close()
            raise UnpackParserException(e.args)

        self.entries = []

        data_unpacked = False
        len_unpacked = 0
        try:
            for securetty_line in securetty_file:
                line = securetty_line.rstrip()
                match_result = RE_TTY.match(line)
                if not match_result:
                    continue
                len_unpacked += len(securetty_line)
                self.entries.append(match_result.groups()[0])
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            securetty_file.close()

        check_condition(data_unpacked, "no fstab file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['securetty']

    @property
    def metadata(self):
        metadata = {'terminals': self.entries}
        return metadata
