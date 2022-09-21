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
from . import spreadtrum_pac


class SpreadtrumPacUnpackParser(UnpackParser):
    #extensions = ['.pac']
    extensions = []
    signatures = [(2116, b'\xfa\xff\xfa\xff')]
    pretty_name = 'spreadtrum_pac'

    def parse(self):
        try:
            self.data = spreadtrum_pac.SpreadtrumPac.from_io(self.infile)
            self.unpacked_size = self.data.header.len_file
            product_name = self.data.header.product_name.decode('utf-16-le').split('\x00')[0]
            firmware_name = self.data.header.firmware_name.decode('utf-16-le').split('\x00')[0]
            for entry in self.data.entries.entries:
                self.unpacked_size = max(self.unpacked_size, entry.header.ofs_partition + entry.header.len_partition)
                len_data = len(entry.data)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.infile.size >= self.unpacked_size, "not enough data")

    def unpack(self, meta_directory):
        for entry in self.data.entries.entries:
            if entry.header.len_partition == 0:
                continue
            file_path = pathlib.Path(entry.header.file_name.decode('utf-16-le').split('\x00')[0])
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.data)
                yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['spreadtrum', 'firmware']

    @property
    def metadata(self):
        metadata = {}
        metadata['product_name'] = self.data.header.product_name.decode('utf-16-le').split('\x00')[0]
        metadata['firmware_name'] = self.data.header.firmware_name.decode('utf-16-le').split('\x00')[0]
        return metadata
