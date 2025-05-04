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
from . import android_fbpk


# v1 test file: redfin-rd1a.200810.020-factory-c3ea1715.zip
# v2 test file: raven-sd1a.210817.015.a4-factory-bd6cb030.zip
class AndroidFbpkUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FBPK')
    ]
    pretty_name = 'android_fbpk'

    def parse(self):
        try:
            self.data = android_fbpk.AndroidFbpk.from_io(self.infile)
            # version 2 needs some extra sanity checks
            # read data to trigger evaluation
            if self.data.header.version == 2:
                for entry in self.data.body.entries:
                    # read the parsed partition to trigger
                    # parsing for FBPT entries
                    data = entry.partition_parsed
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e
        self.unpacked_size = self.data.body.total_file_size

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        seen_partitions = set()
        for entry in self.data.body.entries:
            out_labels = []
            # only consider "real" partitions
            if entry.type == 0:
                continue

            is_renamed = False
            orig_name = ''

            partition_name = entry.partition_name
            # there can be duplicates, so rename
            if partition_name in seen_partitions:
                counter = 1
                while True:
                    new_partition_name = f"{entry.partition_name}-renamed-{counter}"
                    if new_partition_name not in seen_partitions:
                        partition_name = new_partition_name
                        is_renamed = True
                        orig_name = entry.partition_name
                        break
                    counter += 1

            file_path = pathlib.Path(partition_name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.partition)

                if is_renamed:
                    with unpacked_md.open(open_file=False):
                        out_labels.append('renamed')
                        unpacked_md.info['labels'] = out_labels
                        unpacked_md.info['metadata'] = {'name': orig_name}
                yield unpacked_md
            seen_partitions.add(partition_name)

    labels = ['android', 'fbpk']
    metadata = {}
