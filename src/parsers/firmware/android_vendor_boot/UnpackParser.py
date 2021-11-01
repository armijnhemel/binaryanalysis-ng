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
from . import android_vendor_boot


class AndroidVendorBootUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'VNDRBOOT')
    ]
    pretty_name = 'android_vendor_boot'

    def parse(self):
        try:
            self.data = android_vendor_boot.AndroidVendorBoot.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        out_labels = []

        if self.data.header.version == 3:
            file_path = 'vendor_ramdisk'
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.vendor_ramdisk.data)
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        elif self.data.header.version == 4:
            ramdisk_counter = 1
            for ramdisk in self.data.vendor_ramdisk_table.entries:
                if ramdisk.name == '':
                    file_path = "ramdisk-%d" % ramdisk_counter
                else:
                    file_path = ramdisk.name
                ramdisk_counter += 1
                outfile_rel = self.rel_unpack_dir / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(ramdisk.ramdisk)
                fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
                unpacked_files.append(fr)

        file_path = 'dtb'
        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.data.dtb)

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android vendor boot', 'android']
        metadata = {}
        metadata['commandline'] = self.data.header.commandline

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
