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

# verify Unix shadow files
# man 5 shadow

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class PasswdUnpackParser(UnpackParser):
    extensions = ['shadow']
    signatures = [
    ]
    pretty_name = 'shadow'

    def parse(self):
        # open the file again, but then in text mode
        try:
            shadow_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            shadow_file.close()
            raise UnpackParserException(e.args)

        self.entries = []

        data_unpacked = False
        len_unpacked = 0
        try:
            for shadow_line in shadow_file:
                line = shadow_line.rstrip()

                # split the line on :
                fields = line.split(':')

                check_condition(len(fields) == 9, "invalid number of entries")
                try:
                   if fields[2] != '':
                       date_last_change = int(fields[2])
                   if fields[3] != '':
                       minimum_password_age = int(fields[3])
                   if fields[4] != '':
                       maximmum_password_age = int(fields[4])
                   if fields[5] != '':
                       password_warning_period = int(fields[5])
                   if fields[6] != '':
                       password_inactivity_period = int(fields[6])
                   if fields[7] != '':
                       account_expiration_date = int(fields[7])
                except ValueError as e:
                    raise UnpackParserException(e.args)

                # store a few entries
                entry = {}
                entry['name'] = fields[0]
                entry['passwd'] = fields[1]

                self.entries.append(entry)

                len_unpacked += len(shadow_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            shadow_file.close()

        check_condition(data_unpacked, "no shadow file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['shadow']

    @property
    def metadata(self):
        metadata = {'entries': self.entries}
        return metadata
