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

import pathlib

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import android_tzdata


class TzdataUnpackParser(UnpackParser):
    extensions = ['tzdata']
    signatures = []
    pretty_name = 'tzdata'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = android_tzdata.AndroidTzdata.from_io(self.infile)

            # first some sanity checks, read the entries
            for entry in self.data.index.entries:
                # compute the unpacked size. Use len(entry.raw_tzif) to force
                # the parser to actually read the data
                self.unpacked_size = max(self.unpacked_size, self.data.ofs_data + entry.ofs_timezone + len(entry.raw_tzif))

            # read the zone tab info
            for entry in self.data.zonetab.entries:
                pass

            self.unpacked_size = max(self.unpacked_size, self.data.ofs_zonetab + len(self.data._raw__m_zonetab))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        for entry in self.data.index.entries:
            out_labels = ['tzif', 'resource']

            file_path = pathlib.Path(entry.zonename)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.raw_tzif)
                with unpacked_md.open(open_file=False):
                    unpacked_md.info['labels'] = out_labels
                yield unpacked_md

        if len(self.data._raw__m_zonetab) != 0:
            file_path = pathlib.Path('zone.tab')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data._raw__m_zonetab)
                with unpacked_md.open(open_file=False):
                    unpacked_md.info['labels'] = []
                yield unpacked_md

    labels = ['resource', 'timezone', 'android']
    metadata = {}
