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

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args)
        self.unpacked_size = self.data.body.total_file_size

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        unpacked_files = []
        seen_partitions = set()
        for entry in self.data.body.entries:
            out_labels = []
            # only consider "real" partitions
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

            file_path = partition_name
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(entry.partition)

            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
            seen_partitions.add(partition_name)

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'fbpk']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
