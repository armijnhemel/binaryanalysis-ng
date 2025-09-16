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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import nb0


class Nb0UnpackParser(UnpackParser):
    extensions = ['.nb0']
    signatures = []
    pretty_name = 'nb0'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = nb0.Nb0.from_io(self.infile)
            for entry in range(0, self.data.num_entries):
                self.unpacked_size = max(self.unpacked_size, self.data.entries[entry].ofs_partition + \
                                         self.data.entries[entry].len_partition + 4 + self.data.num_entries * 64)
                # read data because Kaitai Struct evaluates instances lazily
                len_data = len(self.data.partitions[entry].body)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e
        check_condition(self.unpacked_size <= self.infile.size,
                        "partitions cannot be outside of file")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        seen_partitions = set()
        for i in range(0, self.data.num_entries):
            out_labels = []

            partition_name = self.data.entries[i].name

            # maybe there are duplicates, so rename
            if partition_name == '':
                partition_name = 'unpacked_from _nb0'
            if partition_name in seen_partitions:
                counter = 1
                while True:
                    new_partition_name = f"{partition_name}-renamed-{counter}"
                    if new_partition_name not in seen_partitions:
                        partition_name = new_partition_name
                        out_labels.append('renamed')
                        break
                    counter += 1

            file_path = pathlib.Path(partition_name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.partitions[i].body)
                with unpacked_md.open(open_file=False):
                    # TODO: store original filename in unpacked_md info if renamed
                    unpacked_md.info['labels'] = out_labels
                yield unpacked_md

            seen_partitions.add(partition_name)

    labels = ['android', 'nb0', 'nxp']
    metadata = {}
