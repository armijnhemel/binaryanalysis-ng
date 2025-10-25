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

# verify Unix crontab
# man 5 crontab

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

CRONTAB_KEYS = set(['CRON_TZ', 'HOME', 'LOGNAME', 'MAILFROM', 'MAILTO', 'PATH', 'SHELL'])

RE_CRONTAB = re.compile(r'(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+\w+\s+.*')


class SecureTTYUnpackParser(UnpackParser):
    extensions = ['crontab']
    signatures = [
    ]
    pretty_name = 'crontab'

    def parse(self):
        # open the file again, but then in text mode
        try:
            crontab_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            crontab_file.close()
            raise UnpackParserException(e.args) from e

        data_unpacked = False
        len_unpacked = 0
        try:
            for crontab_line in crontab_file:
                line = crontab_line.rstrip()
                if line.strip() == '':
                    len_unpacked += len(crontab_line)
                    continue

                if line.startswith('#'):
                    len_unpacked += len(crontab_line)
                    continue

                if '=' in line:
                    cron_key, _ = line.split('=', maxsplit=1)
                    if cron_key not in CRONTAB_KEYS:
                        break
                    len_unpacked += len(crontab_line)
                    data_unpacked = True
                    continue

                match_result = RE_CRONTAB.match(line)
                if not match_result:
                    break
                len_unpacked += len(crontab_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            crontab_file.close()

        check_condition(data_unpacked, "no crontab file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['crontab']
    metadata = {}
