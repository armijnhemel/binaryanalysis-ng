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

# verify Unix group files
# man 5 group

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class GroupUnpackParser(UnpackParser):
    extensions = ['group']
    signatures = [
    ]
    pretty_name = 'group'

    def parse(self):
        # open the file again, but then in text mode
        try:
            group_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            group_file.close()
            raise UnpackParserException(e.args)

        self.entries = []

        data_unpacked = False
        len_unpacked = 0
        try:
            for group_line in group_file:
                line = group_line.rstrip()

                # split the line on :
                fields = line.split(':')
                check_condition(len(fields) == 4, "invalid number of entries")

                try:
                    gid = int(fields[2])
                except ValueError as e:
                    raise UnpackParserException(e.args)

                if fields[3] != '':
                    members = fields[3].split(',')
                else:
                    members = []

                entry = {}
                entry['name'] = fields[0]
                entry['passwd'] = fields[1]
                entry['gid'] = gid
                entry['members'] = members

                self.entries.append(entry)

                len_unpacked += len(group_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            group_file.close()

        check_condition(data_unpacked, "no passwd file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['group']

    @property
    def metadata(self):
        metadata = {'entries': self.entries}
        return metadata
