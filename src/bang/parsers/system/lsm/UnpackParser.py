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

# Linux Software Map file
# https://www.ibiblio.org/pub/Linux/docs/linux-software-map/lsm-template (version 3)
# http://www.ibiblio.org/pub/linux/LSM-TEMPLATE.html (version 4)

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class LsmUnpackParser(UnpackParser):
    extensions = ['.lsm']
    signatures = [
    ]
    pretty_name = 'lsm'

    mandatory_fields = set(['Title', 'Version', 'Entered-date',
                            'Description', 'Author', 'Primary-site'])

    optional_fields = set(['Keywords', 'Maintained-by', 'Alternate-site',
                           'Original-site', 'Platforms', 'Copying-policy'])

    all_fields = mandatory_fields | optional_fields

    def parse(self):
        # open the file again, but then in text mode
        try:
            lsm_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            lsm_file.close()
            raise UnpackParserException(e.args)

        len_unpacked = 0
        is_first_line = True
        has_end = False
        try:
            for lsm_line in lsm_file:
                line = lsm_line.rstrip()

                if line == '':
                    len_unpacked += len(lsm_line)
                    continue

                if is_first_line:
                    check_condition(line in ['Begin3', 'Begin4'], "invalid first line")
                    is_first_line = False
                    if line == 'Begin3':
                        lsm_type = 3
                    else:
                        lsm_type = 4
                    len_unpacked += len(lsm_line)
                    continue

                if line == 'End':
                    has_end = True
                    len_unpacked += len(lsm_line)
                    break

                # continuations (primarily LSM3)
                if line.startswith(' ') or line.startswith('\t'):
                    len_unpacked += len(lsm_line)
                    continue

                # fields are separated by : except in LSM4 "Primary-site"?
                # This isn't clear from the LSM4 spec. LSM4 files seem to
                # suggest that there is a tab or space first
                fields = line.split(':', 1)

                if fields[0] not in self.all_fields:
                    break

                len_unpacked += len(lsm_line)
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            lsm_file.close()

        check_condition(has_end, "no valid LSM file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['lsm']
    metadata = {}
