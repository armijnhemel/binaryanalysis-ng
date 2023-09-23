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

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import linux_x86


class LinuxX86UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (514, b'HdrS')
    ]
    pretty_name = 'linux_x86'

    def parse(self):
        try:
            self.data = linux_x86.LinuxX86.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        self.unpacked_size = self.infile.tell()
        if self.data.header.ofs_payload != 0:
            self.unpacked_size = self.data.header.real_mode_code_size + self.data.header.ofs_payload + self.data.header.len_payload

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        if self.data.header.ofs_payload != 0:
            file_path = pathlib.Path("payload")
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.header.payload)

                with unpacked_md.open(open_file=False):
                    unpacked_md.info['propagated'] = {'parent_parser': self.pretty_name}

                yield unpacked_md

    labels = ['linux_x86']
    metadata = {}
