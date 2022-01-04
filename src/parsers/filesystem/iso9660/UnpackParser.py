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
        try:
            self.data = iso9660.Iso9660.from_io(self.infile)

            # check the contents of the ISO image, also find out where it ends
            for volume_descriptor in self.data.data_area:
                if volume_descriptor.type == iso9660.Iso9660.VolumeType.primary_volume_descriptor:
                    iso_size = volume_descriptor.volume.volume_space_size.value * volume_descriptor.volume.logical_block_size.value
                    check_condition(iso_size <= self.fileresult.filesize,
                                    "declared ISO9660 image bigger than file")
                elif volume_descriptor.type == iso9660.Iso9660.VolumeType.boot_record_volume_descriptor:
                    pass
        except (Exception, ValidationFailedError, UndecidedEndiannessError) as e:
            raise UnpackParserException(e.args)



    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['iso9660', 'filesystem']
        metadata = {}

        for volume_descriptor in self.data.data_area:
            if volume_descriptor.type == iso9660.Iso9660.VolumeType.primary_volume_descriptor:
                pass
            elif volume_descriptor.type == iso9660.Iso9660.VolumeType.boot_record_volume_descriptor:
                pass

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
