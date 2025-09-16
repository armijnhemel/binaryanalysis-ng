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

# verify smbpasswd files
# man 5 smbpasswd

import binascii

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class SmbPasswdUnpackParser(UnpackParser):
    extensions = ['smbpasswd']
    signatures = [
    ]
    pretty_name = 'smbpasswd'

    def parse(self):
        # open the file again, but then in text mode
        try:
            smbpasswd_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            smbpasswd_file.close()
            raise UnpackParserException(e.args) from e

        self.entries = []

        data_unpacked = False
        len_unpacked = 0
        try:
            for shadow_line in smbpasswd_file:
                line = shadow_line.rstrip()

                # split the line on :
                fields = line.split(':')

                check_condition(len(fields) >= 6, "invalid number of entries")
                try:
                    uid = int(fields[1])
                except ValueError as e:
                    raise UnpackParserException(e.args) from e

                # next field is the LANMAN password hash, 32 hex digits, or all X
                check_condition(len(fields[2]) == 32, "invalid LANMAN hash (wrong length)")

                if fields[2] != 32 * 'X':
                    try:
                        binascii.unhexlify(fields[2])
                    except binascii.Error as e:
                        raise UnpackParserException("invalid LANMAN hash") from e

                # next field is the NT password hash, 32 hex digits
                check_condition(len(fields[3]) == 32, "invalid NT password hash (wrong length)")
                try:
                    binascii.unhexlify(fields[3])
                except binascii.Error as e:
                    raise UnpackParserException("invalid NT password hash") from e

                # next field is accountflags, always 13 characters
                check_condition(len(fields[4]) == 13, "invalid account flags (wrong length)")

                # account flags always include brackets
                check_condition(fields[4][0] == '[' and fields[4][-1] == ']',
                                "invalid account flags (no brackets)")

                # last changed field
                check_condition(fields[5].startswith('LCT-'), "invalid last changed field")

                # store a few entries
                entry = {}
                entry['name'] = fields[0]
                entry['uid'] = uid
                entry['lanman'] = fields[2]
                entry['ntpasswd'] = fields[3]
                entry['flags'] = fields[4][1:-1].strip()
                entry['changed'] = fields[5][4:]

                self.entries.append(entry)

                len_unpacked += len(shadow_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            smbpasswd_file.close()

        check_condition(data_unpacked, "no shadow file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['smbpasswd']

    @property
    def metadata(self):
        metadata = {'entries': self.entries}
        return metadata
