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

# $ man 5 modules.dep

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

RE_MODULES_DEP = re.compile(r'/[\w\d\.\-_/]+:(.*)')


class ModulesDep(UnpackParser):
    extensions = ['modules.dep']
    signatures = [
    ]
    pretty_name = 'modules.dep'

    def parse(self):
        # open the file again, but then in text mode
        try:
            modules_dep_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            modules_dep_file.close()
            raise UnpackParserException(e.args) from e

        data_unpacked = False
        len_unpacked = 0
        try:
            for modules_dep_line in modules_dep_file:
                line = modules_dep_line.rstrip()
                len_modules_dep_line = len(modules_dep_line)
                if line.strip() == '':
                    len_unpacked += len_modules_dep_line
                    continue

                if line.startswith('#'):
                    len_unpacked += len_modules_dep_line
                    continue

                match_result = RE_MODULES_DEP.match(line)
                if not match_result:
                    break
                len_unpacked += len_modules_dep_line
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            modules_dep_file.close()

        check_condition(data_unpacked, "no modules.dep file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['modules.dep']
    metadata = {}
