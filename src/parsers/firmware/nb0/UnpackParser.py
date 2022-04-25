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
            raise UnpackParserException(e.args)
        check_condition(self.unpacked_size <= self.fileresult.filesize,
                        "partitions cannot be outside of file")

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        unpacked_files = []
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
                    new_partition_name = "%s-renamed-%d" % (partition_name, counter)
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
            outfile.write(self.data.partitions[i].body)

            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
            seen_partitions.add(partition_name)

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'nb0', 'nxp']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
