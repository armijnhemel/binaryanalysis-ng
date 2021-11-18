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

import os
import pathlib
import shutil
import subprocess

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import zchunk


class ZchunkUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\0ZCK1')
    ]
    pretty_name = 'zchunk'

    def parse(self):
        if shutil.which('unzck') is None:
            raise UnpackParserException("unzck not installed")
        try:
            self.data = zchunk.Zchunk.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.zck':
            file_path = pathlib.Path(meta_directory.file_path.stem)
        else:
            file_path = pathlib.Path("unpacked_from_zchunk")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # TODO: find a way to deal with offsets in input file
            p = subprocess.Popen(['unzck', '-c', meta_directory.file_path], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()
            check_condition(p.returncode == 0, "zck unpacking error")
            yield unpacked_md

    labels = ['zchunk', 'compressed']
    metadata = {}

