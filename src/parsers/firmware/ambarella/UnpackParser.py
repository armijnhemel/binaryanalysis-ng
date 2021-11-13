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
import binascii
from FileResult import FileResult
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ambarella


class AmbarellaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x818, b'\x90\xeb\x24\xa3')
    ]
    pretty_name = 'ambarella'

    def parse(self):
        file_size = self.fileresult.filesize
        try:
            self.data = ambarella.Ambarella.from_io(self.infile)

            # hack: read all data
            for section in self.data.sections:
                if section.body is None:
                    continue
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = 256
        for i in range(len(self.data.start_offsets)):
            self.unpacked_size = max(self.unpacked_size, self.data.end_offsets[i])
        check_condition(file_size >= self.unpacked_size, "not enough data")

        for section in self.data.sections:
            if section.body is None:
                continue
            computed_crc = binascii.crc32(section.body.data)
            check_condition(section.body.header.crc32 == computed_crc, "invalid CRC")

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        # section to name, from:
        # http://web.archive.org/web/20140627194326/http://forum.dashcamtalk.com/threads/r-d-a7-r-d-thread.5119/page-2
        # post #28
        #
        # These names are NOT recorded in the binary!
        section_to_name = {0: 'bootstrap',
                           2: 'bootloader',
                           5: 'rtos',
                           8: 'ramdisk',
                           9: 'romfs',
                           10: 'dsp',
                           11: 'linux'}

        unpacked_files = []
        for section in self.data.sections:
            if section.body is None:
                continue

            outfile_rel = self.rel_unpack_dir / section_to_name.get(section.i, str(section.i))
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(section.body.data)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ambarella']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
