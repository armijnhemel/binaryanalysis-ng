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
from . import android_img_lk


class AndroidBootImgUnpacker(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ANDROID!')
    ]
    pretty_name = 'android_boot_img'


    def parse(self):
        file_size = self.fileresult.filesize
        self.is_variant = False
        try:
            self.data = android_img.AndroidImg.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            try:
                self.infile.seek(self.offset)
                self.data = android_img_lk.AndroidImgLk.from_io(self.infile)
                self.is_variant = True
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)

        self.unpacked_size = self.infile.tell()

        # compute the size and check against the file size
        # take padding into account
        if self.is_variant:
            self.unpacked_size = max(self.unpacked_size, self.data.header.dtb_pos + self.data.header.dt_size)
        else:
            if self.data.header_version < 3:
                page_size = self.data.header.page_size
                try:
                    unpacked_size = ((page_size + self.data.header.kernel.size + page_size - 1)//page_size) * page_size
                except ZeroDivisionError as e:
                    raise UnpackParserException(e.args)
                if self.data.header.ramdisk.size > 0:
                    unpacked_size = ((unpacked_size + self.data.header.ramdisk.size + page_size - 1)//page_size) * page_size
                if self.data.header.second.size > 0:
                    unpacked_size = ((unpacked_size + self.data.header.second.size + page_size - 1)//page_size) * page_size
                if self.data.header_version > 0:
                    if self.data.header.recovery_dtbo.size > 0:
                        unpacked_size = ((self.data.header.recovery_dtbo.offset + self.data.header.recovery_dtbo.size + page_size - 1)//page_size) * page_size
                if self.data.header_version > 1:
                    if self.data.header.dtb.size > 0:
                        unpacked_size = ((unpacked_size + self.data.header.dtb.size + page_size - 1)//page_size) * page_size
                self.unpacked_size = max(self.unpacked_size, unpacked_size)
                check_condition(file_size >= self.unpacked_size, "not enough data")
            elif self.data.header_version in [3, 4]:
                unpacked_size = 4096 + len(self.data.header.kernel_img) + \
                    len(self.data.header.padding1) + len(self.data.header.ramdisk_img) + \
                    len(self.data.header.padding2)
                self.unpacked_size = max(self.unpacked_size, unpacked_size)

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
        outfile.write(self.data.header.kernel_img)
        outfile.close()
        fr = FileResult(self.fileresult, outfile_rel, set([]))
        unpacked_files.append(fr)

        if self.data.header.ramdisk.size > 0:
            outfile_rel = self.rel_unpack_dir / ramdisk_name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.data.header.ramdisk_img)
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)

        if self.is_variant:
            if self.data.header.second.size > 0:
                outfile_rel = self.rel_unpack_dir / secondstage_name
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(self.data.header.second_img)
                outfile.close()
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                unpacked_files.append(fr)
            if self.data.header.dt_size> 0:
                outfile_rel = self.rel_unpack_dir / dtb_name
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(self.data.header.dtb)
                outfile.close()
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                unpacked_files.append(fr)
        else:
            if self.data.header_version < 3:
                if self.data.header.second.size > 0:
                    outfile_rel = self.rel_unpack_dir / secondstage_name
                    outfile_full = self.scan_environment.unpack_path(outfile_rel)
                    os.makedirs(outfile_full.parent, exist_ok=True)
                    outfile = open(outfile_full, 'wb')
                    outfile.write(self.data.header.second_img)
                    outfile.close()
                    fr = FileResult(self.fileresult, outfile_rel, set([]))
                    unpacked_files.append(fr)
                if self.data.header_version > 0:
                    if self.data.header.recovery_dtbo.size > 0:
                        outfile_rel = self.rel_unpack_dir / recovery_name
                        outfile_full = self.scan_environment.unpack_path(outfile_rel)
                        os.makedirs(outfile_full.parent, exist_ok=True)
                        outfile = open(outfile_full, 'wb')
                        outfile.write(self.data.header.recovery_dtbo_img)
                        outfile.close()
                        fr = FileResult(self.fileresult, outfile_rel, set([]))
                        unpacked_files.append(fr)
                if self.data.header_version > 1:
                    if self.data.header.dtb.size > 0:
                        outfile_rel = self.rel_unpack_dir / dtb_name
                        outfile_full = self.scan_environment.unpack_path(outfile_rel)
                        os.makedirs(outfile_full.parent, exist_ok=True)
                        outfile = open(outfile_full, 'wb')
                        outfile.write(self.data.header.dtb_img)
                        outfile.close()
                        fr = FileResult(self.fileresult, outfile_rel, set([]))
                        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'android', "android boot image"]
        if self.is_variant:
            labels.append('lk variant')
        metadata = {'version': self.data.header_version}

        if self.data.header.name != '':
            metadata = {'name': self.data.header.name}
        if self.data.header.cmdline != '':
            metadata = {'cmdline': self.data.header.cmdline}
        if not self.is_variant:
            if self.data.header.extra_cmdline != '':
                try:
                    metadata = {'extra_cmdline': self.data.header.extra_cmdline.decode()}
                except:
                    pass
            metadata['version'] = {'major': self.data.header.os_version.major,
                                   'minor': self.data.header.os_version.minor,
                                   'patch': self.data.header.os_version.patch,
                                   'year': self.data.header.os_version.year,
                                   'month': self.data.header.os_version.month,
                                  }

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
