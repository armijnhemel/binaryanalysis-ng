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

# parse Subversion *wcprops files
# file `subversion/libsvn_subr/hash.c` in the Subversion source code has
# a specification, but you should also inspect some real files.

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class SubversionHashUnpackParser(UnpackParser):
    extensions = ['wcprops']
    signatures = [
    ]
    pretty_name = 'subversion_hash'

    def parse(self):
        # open the file again, but then in text mode
        try:
            svn_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            svn_file.close()
            raise UnpackParserException(e.args)

        data_unpacked = False
        len_unpacked = 0
        next_action = 'start'

        # a line can be either:
        #
        # 1. some sort of header (example: file name) which may
        #    or may not be present. This can be seen as a context
        #    for the key/value pairs. The first entry typically does
        #    not have a header/context, but subsequent entries do,
        #    usually a file name.
        # 2. a key indicator, followed by the length of the key
        # 3. a key
        # 4. a value indicator, followed by the length of the value
        # 5. a value
        # 6. END

        try:
            # simple state machine for processing lines
            end_of_previous_kv = 0
            for svn_line in svn_file:
                line = svn_line.rstrip()

                if next_action == 'filename':
                    lineres = re.match(r'[\w\d\!\./-]+$', line)
                    next_action = 'start'
                    if lineres is not None:
                        len_unpacked += len(svn_line)
                        continue

                if next_action == 'start':
                    lineres = re.match(r'K (\d+)$', line)
                    if lineres is None:
                        break
                    linelength = int(lineres.groups()[0])
                    next_action = 'data'
                elif next_action == 'data':
                    if linelength != len(line):
                        break
                    next_action = 'value'
                elif next_action == 'value':
                    if line.rstrip() == 'END':
                        data_unpacked = True
                        next_action = 'filename'
                        len_unpacked += len(svn_line)
                        end_of_previous_kv = len_unpacked
                        continue
                    else:
                        lineres = re.match(r'V (\d+)$', line)
                        if lineres is None:
                            break
                        linelength = int(lineres.groups()[0])
                        next_action = 'data'
                len_unpacked += len(svn_line)
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            svn_file.close()

        check_condition(data_unpacked, "no subversion hash data could be unpacked")
        self.unpacked_size = end_of_previous_kv

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['subversion_hash']
    metadata = {}
