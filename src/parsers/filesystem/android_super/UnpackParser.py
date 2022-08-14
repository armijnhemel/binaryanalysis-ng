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
from . import android_super

class AndroidSuperUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x1000, b'gDla')
    ]
    pretty_name = 'android_super'

    def parse(self):
        # store partitions and extents 
        self.partitions = {}
        self.extents = {}
        self.unpacked_size = 0

        try:
            self.data = android_super.AndroidSuper.from_io(self.infile)

            logical_block_size = self.data.root.primary_geometry.logical_block_size

            # read data to force kaitai struct to validate
            for meta in self.data.root.primary_metadata:

                # partitions
                partition_counter = 0
                for partition in meta.partitions.table:
                    if partition_counter not in self.partitions:
                        self.partitions[partition_counter] = {'name': partition.name,
                                                              'first_extent': partition.first_extent_index,
                                                              'num_extents': partition.num_extents}
                    else:
                        check_condition(self.partitions[partition_counter] == {'name': partition.name,
                                                              'first_extent': partition.first_extent_index,
                                                              'num_extents': partition.num_extents},
                                        "out of sync metadata (partitions)")
                    partition_counter += 1

                # extents
                extents_counter = 0
                for extent in meta.extents.table:
                    if extent.target_type == android_super.AndroidSuper.Metadata.Extent.TargetType.linear:
                        physical_offset = extent.target_data * self.data.sector_size
                        if extents_counter not in self.extents:
                            self.extents[extents_counter] = {'size': extent.extent_size, 'offset': physical_offset}
                        else:
                            check_condition(self.extents[extents_counter] == {'size': extent.extent_size, 'offset': physical_offset},
                                            "out of sync metadata (extents)")
                    else:
                        check_condition(extent.target_data == 0, "invalid value for target_data")
                    extents_counter += 1

            # ignore backup metadata for now
            for meta in self.data.root.backup_metadata:
                pass

        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # sanity check the partitions and extents
        for partition in self.partitions:

            # extents are consecutive and should exist
            for i in range(0, self.partitions[partition]['num_extents']):
                extent_number = self.partitions[partition]['first_extent'] + i
                check_condition(extent_number in self.extents, "invalid extent number")
                check_condition(self.extents[extent_number]['offset'] + self.extents[extent_number]['size'] <= self.fileresult.filesize,
                                "extent too large for file")
                self.unpacked_size = self.extents[extent_number]['offset'] + self.extents[extent_number]['size']
                
    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []

        # write partitions
        for partition in self.partitions:
            if self.partitions[partition]['num_extents'] == 0:
                # skip partitions that have no data associated with them
                continue

            out_labels = []

            file_path = self.partitions[partition]['name']
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)

            # extents are consecutive and should exist
            for i in range(0, self.partitions[partition]['num_extents']):
                extent_number = self.partitions[partition]['first_extent'] + i
                self.extract_to_file(outfile_full, self.extents[extent_number]['offset'], self.extents[extent_number]['size'])
                check_condition(extent_number in self.extents, "invalid extent number")

            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)

        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'android super']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
