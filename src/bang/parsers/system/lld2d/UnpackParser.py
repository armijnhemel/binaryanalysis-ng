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

# configuration file for proprietary lltd daemon as found in (amongst
# others) older Realtek based devices
# https://web.archive.org/web/20210303145227/https://www.osslab.com.tw/wp-content/uploads/2017/01/Kernel-2_6-SDK-User-Guide-v1_12.pdf

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

RE_FILE_LOCATION = re.compile(r'/[\w\d\.\-_/]*\.ico$')

class Lld2d_conf(UnpackParser):
    extensions = ['lld2d.conf']
    signatures = [
    ]
    pretty_name = 'lld2d.conf'

    def parse(self):
        # open the file again, but then in text mode
        try:
            lld2d_conf_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            lld2d_conf_file.close()
            raise UnpackParserException(e.args) from e

        data_unpacked = False
        len_unpacked = 0
        try:
            for conf_line in lld2d_conf_file:
                line = conf_line.rstrip()
                len_conf_line = len(conf_line)
                if line.strip() == '':
                    len_unpacked += len_conf_line
                    continue

                if line.startswith('#'):
                    len_unpacked += len_conf_line
                    continue

                keyword, value = line.split('=', maxsplit=1)
                if keyword.strip() not in ['icon', 'jumbo-icon']:
                    break
                if not RE_FILE_LOCATION.match(value.strip()):
                    break

                len_unpacked += len_conf_line
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            lld2d_conf_file.close()

        check_condition(data_unpacked, "no host.conf file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['lld2d.conf']
    metadata = {}
