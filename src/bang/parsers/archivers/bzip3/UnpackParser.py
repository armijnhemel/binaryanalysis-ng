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
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import bzip3


class Bzip3UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BZ3v1')
    ]
    pretty_name = 'bzip3'

    def parse(self):
        check_condition(shutil.which('bzip3') is not None,
                        "bzip3 program not found")
        try:
            self.data = bzip3.Bzip3.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = self.infile.tell()

        # Test unpack the data, first reset the offset
        self.infile.seek(0)

        # test unpack to /dev/null to see if the data is valid
        # read the entire contents of the file and pipe to bzip3
        p = subprocess.Popen(['bzip3', '-c', '-d'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate(self.infile.read(self.unpacked_size))

        check_condition(p.returncode == 0, "bzip3 unpacking error")


    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.bz3':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_bz3")
        elif meta_directory.file_path.suffix.lower() in ['.tbz3', '.tb3', '.tarbz3']:
            file_path = pathlib.Path(meta_directory.file_path.stem + ".tar")
        else:
            file_path = pathlib.Path("unpacked_from_bz3")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # First reset the offset
            self.infile.seek(0)

            # read the entire contents of the file and pipe to bzip3
            p = subprocess.Popen(['bzip3', '-c', '-d'], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate(self.infile.read(self.unpacked_size))

            yield unpacked_md

    labels = ['bzip3', 'compressed']
    metadata = {}
