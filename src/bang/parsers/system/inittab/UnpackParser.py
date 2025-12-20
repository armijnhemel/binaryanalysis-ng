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
#
# https://web.archive.org/web/20240718014124/https://man.cx/inittab(4)


from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

# valid inittab actions, includes BusyBox specific actions
VALID_ACTIONS = ['respawn', 'wait', 'once', 'boot', 'bootwait', 'powerfail',
                 'powerwait', 'off', 'ondemand', 'initdefault', 'sysinit',
                 'askfirst', 'ctrlaltdel', 'restart', 'shutdown']

class Inittab(UnpackParser):
    extensions = ['inittab']
    signatures = [
    ]
    pretty_name = 'inittab'

    def parse(self):
        # open the file again, but then in text mode
        try:
            conf_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            conf_file.close()
            raise UnpackParserException(e.args) from e

        data_unpacked = False
        len_unpacked = 0
        try:
            for conf_line in conf_file:
                line = conf_line.rstrip()
                len_conf_line = len(conf_line)
                if line.strip() == '':
                    len_unpacked += len_conf_line
                    continue

                if line.startswith('#'):
                    len_unpacked += len_conf_line
                    continue

                init_id, rstate, action, process = line.split(':', maxsplit=3)
                if action not in VALID_ACTIONS:
                    break

                len_unpacked += len_conf_line
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            conf_file.close()

        check_condition(data_unpacked, "no inittab file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['inittab']
    metadata = {}
