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

# /usr/share/magic
# https://en.wikipedia.org/wiki/Compress
# https://github.com/vapier/ncompress/releases
# https://wiki.wxwidgets.org/Development:_Z_File_Format


import os
import subprocess
import shutil

from FileResult import FileResult

from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_compress

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


#class CompressUnpackParser(UnpackParser):
class CompressUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1f\x9d')
    ]
    pretty_name = 'compress'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_compress(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        if shutil.which('uncompress') is None:
            check_condition(shutil.which('uncompress-ncompress') is not None,
                            'uncompress program not found')
            uncompress = 'uncompress-ncompress'
        else:
            uncompress = 'uncompress'

        bytes_read = 0
        self.infile.seek(2, os.SEEK_CUR)

        # the next byte contains the "bits per code" field
        # which has to be between 9 (inclusive) and 16 (inclusive)
        flags = self.infile.peek(1)
        check_condition(len(flags) != 0, 'no flags read')

        bitspercode = flags[0] & 0x1f
        check_condition(bitspercode >= 9 and bitspercode <= 16,
                        'invalid bits per code')

        # seek back to the starting point
        self.infile.seek(-2, os.SEEK_CUR)

        # like deflate compress can work on streams
        # As a test some data can be uncompressed.
        # read some test data
        testdata = self.infile.read(1024)

        # ...and run 'uncompress' to see if anything can be compressed at all
        p = subprocess.Popen([uncompress], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (standard_out, standard_error) = p.communicate(testdata)
        check_condition(len(standard_out) != 0, 'invalid compress\'d data')

    def unpack(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['compress']

        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
