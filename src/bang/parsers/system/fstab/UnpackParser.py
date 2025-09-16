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

# verify Unix fstab
# man 5 fstab

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class FstabUnpackParser(UnpackParser):
    extensions = ['fstab']
    signatures = [
    ]
    pretty_name = 'fstab'

    def parse(self):
        # open the file again, but then in text mode
        try:
            fstab_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            fstab_file.close()
            raise UnpackParserException(e.args) from e

        self.entries = []

        data_unpacked = False
        len_unpacked = 0
        try:
            for fstab_line in fstab_file:
                line = fstab_line.rstrip()

                if line == '':
                    len_unpacked += len(fstab_line)
                    continue
                if line.startswith('#'):
                    len_unpacked += len(fstab_line)
                    continue

                # fields are separated by whitespace
                fields = line.split()

                check_condition(len(fields) >= 4, "too few entries")
                check_condition(len(fields) <= 6, "too many entries")

                # store a few entries
                entry = {}
                entry['device'] = fields[0]
                entry['path'] = fields[1]
                entry['fstype'] = fields[2]
                entry['options'] = fields[3].split(',')
                if len(fields) > 4:
                    entry['frequency'] = fields[4]
                if len(fields) > 5:
                    entry['pass'] = fields[5]

                self.entries.append(entry)

                len_unpacked += len(fstab_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            fstab_file.close()

        check_condition(data_unpacked, "no fstab file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['fstab']

    @property
    def metadata(self):
        metadata = {'entries': self.entries}
        return metadata
