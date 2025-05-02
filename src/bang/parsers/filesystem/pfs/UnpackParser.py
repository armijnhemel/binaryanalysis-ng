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

# https://web.archive.org/web/20120511095357/https://0entropy.blogspot.com/2011/08/firmware-reverse-engineering.html
# Test firmware (40 bytes file entry): https://www.touslesdrivers.com/index.php?v_page=23&v_code=15240&v_langue=en

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import pfs
from . import pfs_40


class PfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PFS/0.9\x00')
    ]
    pretty_name = 'pfs'

    def parse(self):
        try:
            self.data = pfs.Pfs.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            self.infile.infile.seek(self.infile.offset)
            try:
                self.data = pfs_40.Pfs40.from_io(self.infile)
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)

        self.unpacked_size = self.infile.tell()
        try:
            # walk the entries to see if they have data
            for entry in self.data.files:
                self.unpacked_size = max(self.unpacked_size, entry.pos + len(entry.data))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        unpacked_files = []

        for entry in self.data.files:
            # file paths are stored as Windows paths
            file_path = pathlib.PureWindowsPath(entry.name)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.data)
                yield unpacked_md

    labels = ['pfs', 'filesystem']
    metadata = {}
