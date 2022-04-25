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

# https://www.sciencedirect.com/science/article/pii/S1742287610000435

import collections
import os
import pathlib

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_iso9660

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError, UndecidedEndiannessError
from . import iso9660


class Iso9660UnpackParser(WrappedUnpackParser):
#class Iso9660UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (32769, b'CD001')
    ]
    pretty_name = 'iso9660'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_iso9660(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        self.zisofs = False
        try:
            self.data = iso9660.Iso9660.from_io(self.infile)

            has_primary = False
            has_terminator = False

            # check the contents of the ISO image
            for descriptor in self.data.data_area:
                if descriptor.type == iso9660.Iso9660.VolumeType.primary:
                    # sanity checks: dates. This does not apply
                    # to all dates used in the specification.
                    check_condition(descriptor.volume.volume_creation_date_and_time.valid_date,
                                    "invalid creation date")

                    check_condition(descriptor.volume.volume_modification_date_and_time.valid_date,
                                    "invalid modification date")

                    has_primary = True
                    iso_size = descriptor.volume.volume_space_size.value * descriptor.volume.logical_block_size.value
                    check_condition(iso_size <= self.fileresult.filesize,
                                    "declared ISO9660 image bigger than file")

                    extent_size = descriptor.volume.root_directory.body.extent.value * descriptor.volume.logical_block_size.value
                    check_condition(extent_size <= self.fileresult.filesize,
                                    "extent cannot be outside of file")

                    # process the root directory.

                    # ECMA 119, 7.6: file name for root directory is 0x00
                    # Some ISO file systems instead set it to 0x01, which
                    # according to 6.8.2.2 should not be for the first root
                    # entry.
                    # Seen in an ISO file included in an ASUS firmware file
                    # Modem_FW_4G_AC55U_30043808102_M14.zip

                    files = collections.deque()
                    if descriptor.volume.root_directory.body.directory_records is not None:
                        for record in descriptor.volume.root_directory.body.directory_records.records:
                            if record.len_dr == 0:
                                continue
                            if record.body.file_flags_directory:
                                if record.body.file_id_dir not in ['\x00', '\x01']:
                                    files.append(record)
                            else:
                                files.append(record)

                    while(len(files) != 0):
                        record = files.popleft()
                        extent_size = record.body.extent.value * descriptor.volume.logical_block_size.value
                        check_condition(extent_size <= self.fileresult.filesize,
                                        "extent cannot be outside of file")

                        if record.body.directory_records is None:
                            continue
                        for dir_record in record.body.directory_records.records:
                            if dir_record.len_dr == 0:
                                continue
                            if dir_record.body.file_flags_directory:
                                if dir_record.body.file_id_dir not in ['\x00', '\x01']:
                                    files.append(dir_record)
                            else:
                                files.append(dir_record)
                elif descriptor.type == iso9660.Iso9660.VolumeType.boot_record:
                    pass
                elif descriptor.type == iso9660.Iso9660.VolumeType.set_terminator:
                    # there should be at least one volume descriptor set terminator
                    has_terminator = True
        except (Exception, ValidationFailedError, UndecidedEndiannessError) as e:
            raise UnpackParserException(e.args)

        check_condition(has_primary, "no primary volume descriptor found")
        check_condition(has_terminator, "no volume descriptor set terminator found")
        self.unpacked_size = iso_size

    def unpack(self):
        unpacked_files = []

        # check the contents of the ISO image
        for descriptor in self.data.data_area:
            if descriptor.type == iso9660.Iso9660.VolumeType.primary:

                # process the root directory.
                files = collections.deque()
                if descriptor.volume.root_directory.body.directory_records is not None:
                    for record in descriptor.volume.root_directory.body.directory_records.records:
                        if record.len_dr == 0:
                            continue
                        if record.body.file_flags_directory:
                            if record.body.file_id_dir not in ['\x00', '\x01']:
                                files.append(record)
                        else:
                            files.append(record)

                while(len(files) != 0):
                    record = files.popleft()

                    if record.body.directory_records is None:
                        continue

                    # add the contents of a directory to the queue
                    for dir_record in record.body.directory_records.records:
                        # first create the directory

                        # then add the contents of the directory to the queue
                        if dir_record.len_dr == 0:
                            continue
                        if dir_record.body.file_flags_directory:
                            if dir_record.body.file_id_dir not in ['\x00', '\x01']:
                                files.append(dir_record)
                        else:
                            files.append(dir_record)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['iso9660', 'filesystem']
        metadata = {}

        for volume_descriptor in self.data.data_area:
            if volume_descriptor.type == iso9660.Iso9660.VolumeType.primary:
                pass
            elif volume_descriptor.type == iso9660.Iso9660.VolumeType.boot_record:
                metadata['bootable'] = True

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
