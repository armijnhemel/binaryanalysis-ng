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

# https://en.wikipedia.org/wiki/TRANS.TBL

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class TranstblUnpackParser(UnpackParser):
    extensions = ['trans.tbl']
    signatures = [
    ]
    pretty_name = 'trans.tbl'

    def parse(self):
        # open the file again, but then in text mode
        try:
            trans_tbl_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            trans_tbl_file.close()
            raise UnpackParserException(e.args)

        self.is_android = False

        data_unpacked = False
        len_unpacked = 0
        try:
            for trans_tbl_line in trans_tbl_file:
                line_splits = trans_tbl_line.strip().split()
                if len(line_splits) != 3:
                    break

                # check if the line has the correct file type indicator:
                # * file
                # * directory
                # * link
                # * fifo
                # (missing: sockets and device files)
                if line_splits[0] not in ['F', 'D', 'L', 'P']:
                    break

                len_unpacked += len(trans_tbl_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            trans_tbl_file.close()

        check_condition(data_unpacked, "no trans.tbl file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['trans.tbl', 'resource']
    metadata = {}
