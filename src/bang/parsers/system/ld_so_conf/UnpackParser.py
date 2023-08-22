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

# verify very simple ld.so.conf files
# This does not process 'include' statements

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class LdSoConfUnpackParser(UnpackParser):
    extensions = ['ld.so.conf']
    signatures = [
    ]
    pretty_name = 'ld.so.conf'

    def parse(self):
        # open the file again, but then in text mode
        try:
            ld_so_conf = open(self.infile.name, 'r', newline='')
        except Exception as e:
            ld_so_conf.close()
            raise UnpackParserException(e.args)

        data_unpacked = False
        len_unpacked = 0
        try:
            for ld_so_line in ld_so_conf:
                line = ld_so_line.rstrip()

                # comments and empty lines are allowed
                if line == '' or line.startswith('#'):
                    len_unpacked += len(ld_so_line)
                    continue

                # TODO: process include statements

                ld_dir = pathlib.PurePosixPath(line)
                check_condition(ld_dir.is_absolute(), "ld.so.conf can only have absolute paths")

                len_unpacked += len(ld_so_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            ld_so_conf.close()

        check_condition(data_unpacked, "no ld.so.conf data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['ld.so.conf']
    metadata = {}
