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

import base64
import binascii
import os
import pathlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

from UnpackParser import WrappedUnpackParser
from bangtext import unpack_base64


class Base64UnpackParser(WrappedUnpackParser):
#class Base64UnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'base64'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_base64(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        check_condition('pak' not in self.fileresult.parentlabels,
                        'parent file Chrome PAK')
        bytes_read = 0

        # add a cut off value to prevent many false positives
        base64cutoff = 8

        # open the file again, but then in text mode
        base64_file = open(self.infile.name, 'r')

        data_unpacked = False

        # in case there is an error store the error message
        # and process it later. This cannot be done with
        # check_condition as this doesn't close base64_file
        error_msg = ''

        # first check to see if the file has consistent
        # line wrapping and if there are any characters
        # that are not in any known base16/32/64 alphabets
