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
from . import sunplus


class SunplusUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'SUNP BURN FILE\x00\x00')
    ]
    pretty_name = 'sunplus'

    def parse(self):
        file_size = self.fileresult.filesize
        try:
            self.data = sunplus.Sunplus.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []

        outfile_rel = self.rel_unpack_dir / 'isp_bootloader'
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.data.isp_bootloader)
        outfile.close()
        fr = FileResult(self.fileresult, outfile_rel, set([]))
        unpacked_files.append(fr)

        if self.data.len_aimg != 0:
            outfile_rel = self.rel_unpack_dir / 'aimg'
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.aimg)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)

        # TODO: split this further into two FAT images
        # see https://github.com/Linouth/iCatch-V50-Playground
        if self.data.len_bimg != 0:
            outfile_rel = self.rel_unpack_dir / 'bimg'
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.bimg)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)

        if self.data.len_cimg != 0:
            outfile_rel = self.rel_unpack_dir / 'cimg'
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.cimg)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)

        if self.data.len_bin != 0:
            outfile_rel = self.rel_unpack_dir / 'bin'
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.bin)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)

        if self.data.len_bad_pixel != 0:
            outfile_rel = self.rel_unpack_dir / 'bad_pixel'
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.bad_pixel)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)

        if self.data.len_dram != 0:
            outfile_rel = self.rel_unpack_dir / 'dram'
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.dram)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['sunplus', 'firmware']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
