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

# verify various types of Unix passwd files
# man 5 passwd
# https://www.freebsd.org/cgi/man.cgi?query=passwd&sektion=5

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class PasswdUnpackParser(UnpackParser):
    extensions = ['passwd']
    signatures = [
    ]
    pretty_name = 'passwd'

    def parse(self):
        # open the file again, but then in text mode
        try:
            passwd_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            passwd_file.close()
            raise UnpackParserException(e.args) from e

        self.entries = []

        data_unpacked = False
        len_unpacked = 0
        num_fields = 0
        try:
            for passwd_line in passwd_file:
                line = passwd_line.rstrip()

                # split the line on :
                fields = line.split(':')
                if num_fields == 0:
                    num_fields = len(fields)
                    check_condition(num_fields in [7, 10],
                                    "invalid number of entries (not 7 or 10)")

                check_condition(len(fields) == num_fields,
                                "invalid number of entries, mixed passwd file?")

                try:
                    uid = int(fields[2])
                    gid = int(fields[3])
                except ValueError as e:
                    raise UnpackParserException(e.args) from e

                entry = {}
                entry['name'] = fields[0]
                entry['passwd'] = fields[1]
                entry['uid'] = uid
                entry['gid'] = gid

                if num_fields == 7:
                    entry['gecos'] = fields[4]
                    entry['directory'] = fields[5]
                    entry['shell'] = fields[6]
                elif num_fields == 10:
                    entry['class'] = fields[4]
                    entry['change'] = fields[5]
                    entry['expire'] = fields[6]
                    entry['gecos'] = fields[7]
                    entry['directory'] = fields[8]
                    entry['shell'] = fields[9]

                self.entries.append(entry)

                len_unpacked += len(passwd_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            passwd_file.close()

        check_condition(data_unpacked, "no passwd file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['passwd']

    @property
    def metadata(self):
        metadata = {'entries': self.entries}
        return metadata
