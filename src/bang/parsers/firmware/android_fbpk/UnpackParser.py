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
from FileResult import FileResult

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import android_fbpk


# test file: redfin-rd1a.200810.020-factory-c3ea1715.zip
class AndroidFbpkUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FBPK')
    ]
    pretty_name = 'android_fbpk'

    def parse(self):
        try:
            self.data = android_fbpk.AndroidFbpk.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        seen_partitions = set()
        for entry in self.data.entries:
            out_labels = []
            # only consider "real" partitions, not partition tables
            if entry.type == 0:
                continue
            partition_name = entry.partition_name
            # there can be duplicates, so rename
            if partition_name in seen_partitions:
                counter = 1
                while True:
                    new_partition_name = "%s-renamed-%d" % (entry.partition_name, counter)
                    if new_partition_name not in seen_partitions:
                        partition_name = new_partition_name
                        out_labels.append('renamed')
                        break
                    counter += 1

            file_path = pathlib.Path(partition_name)
            with meta_directory.unpack_results(file_path) as (unpacked_md, outfile):
                outfile.write(entry.partition)

                with unpacked_md.open(open_file=False):
                    # TODO: add original filename to unpacked_md info if renamed
                    unpacked_md.info['labels'] = out_labels
            seen_partitions.add(partition_name)

    labels = ['android', 'fbpk']
    metadata = {}

