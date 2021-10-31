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

'''
Unpacker for Android images.
'''

import os
import pathlib
from FileResult import FileResult
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_img

from bangandroid import unpack_android_boot_img
from UnpackParser import WrappedUnpackParser

#class AndroidImgUnpacker(UnpackParser):
class AndroidImgUnpacker(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'ANDROID!')
    ]
    pretty_name = 'android_img'


    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_boot_img(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        file_size = self.fileresult.filesize
        try:
            self.data = android_img.AndroidImg.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # right now only look at version < 3
        check_condition(self.data.header_version != 3, "version 3 not suppprted")

        # compute the size and check against the file size
        # take padding into account
        page_size = self.data.page_size
        self.unpacked_size = ((page_size + self.data.kernel.size + page_size - 1)//page_size) * page_size
        if self.data.ramdisk.size > 0:
            self.unpacked_size = ((self.unpacked_size + self.data.ramdisk.size + page_size - 1)//page_size) * page_size
        if self.data.second.size > 0:
            self.unpacked_size = ((self.unpacked_size + self.data.second.size + page_size - 1)//page_size) * page_size
        if self.data.header_version > 0:
            if self.data.recovery_dtbo.size > 0:
                self.unpacked_size = ((self.data.recovery_dtbo.offset + self.data.recovery_dtbo.size + page_size - 1)//page_size) * page_size
        if self.data.header_version > 1:
            if self.data.dtb.size > 0:
                self.unpacked_size = ((self.unpacked_size + self.data.dtb.size + page_size - 1)//page_size) * page_size
        check_condition(file_size >= self.unpacked_size, "not enough data")

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        # the android boot loader images don't have names recorded
        # for the different parts, so just hardcode these.
        kernel_name = 'kernel'
        ramdisk_name = 'ramdisk'
        secondstage_name = 'secondstage'
        recovery_name = 'recovery'
        dtb_name = 'dtb'

        unpacked_files = []

        outfile_rel = self.rel_unpack_dir / kernel_name
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.data.kernel_img)
        outfile.close()
        fr = FileResult(self.fileresult, outfile_rel, set([]))
        unpacked_files.append(fr)

        if self.data.ramdisk.size > 0:
            outfile_rel = self.rel_unpack_dir / ramdisk_name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.ramdisk_img)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)
        if self.data.second.size > 0:
            outfile_rel = self.rel_unpack_dir / secondstage_name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.second_img)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)
        if self.data.header_version > 0:
            if self.data.recovery_dtbo.size > 0:
                outfile_rel = self.rel_unpack_dir / recovery_name
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(self.data.recovery_dtbo_img)
                outfile.close()
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                unpacked_files.append(fr)
        if self.data.header_version > 1:
            if self.data.dtb.size > 0:
                outfile_rel = self.rel_unpack_dir / dtb_name
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(self.data.dtb_img)
                outfile.close()
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'android', "android boot image"]
        metadata = {'version': self.data.header_version}
        if self.data.name != '':
            metadata = {'name': self.data.name}
        if self.data.cmdline != '':
            metadata = {'cmdline': self.data.cmdline}
        if self.data.extra_cmdline != '':
            metadata = {'extra_cmdline': self.data.extra_cmdline}
        metadata['version'] = {'major': self.data.os_version.major,
                               'minor': self.data.os_version.minor,
                               'patch': self.data.os_version.patch,
                               'year': self.data.os_version.year,
                               'month': self.data.os_version.month,
                              }

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
