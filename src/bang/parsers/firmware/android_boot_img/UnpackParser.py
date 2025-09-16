# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

'''
Unpacker for Android images.
'''

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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
        file_size = self.infile.size
        self.is_variant = False
        try:
            self.data = android_img.AndroidImg.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            try:
                # seek to the start of the file
                self.infile.seek(0)
                self.data = android_img_lk.AndroidImgLk.from_io(self.infile)
                self.is_variant = True
            except (Exception, ValidationFailedError) as ex:
                raise UnpackParserException(ex.args) from ex

            check_condition(self.data.header.page_size + self.data.header.kernel.size <= self.infile.size,
                            "data cannot be outside of file")

        self.unpacked_size = self.infile.tell()

        # compute the size and check against the file size
        # take padding into account
        if self.is_variant:
            self.unpacked_size = max(self.unpacked_size, self.data.header.dtb_pos + self.data.header.dt_size)
            check_condition(self.unpacked_size <= self.infile.size,
                            "data cannot be outside of file")
        else:
            if self.data.header_version < 3:
                page_size = self.data.header.page_size
                try:
                    unpacked_size = ((page_size + self.data.header.kernel.size + page_size - 1)//page_size) * page_size
                except ZeroDivisionError as e:
                    raise UnpackParserException(e.args) from e
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

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        # the android boot loader images don't have names recorded
        # for the different parts, so just hardcode these.
        kernel_name = 'kernel'
        ramdisk_name = 'ramdisk'
        secondstage_name = 'secondstage'
        recovery_name = 'recovery'
        dtb_name = 'dtb'

        with meta_directory.unpack_regular_file(pathlib.Path(kernel_name)) as (unpacked_md, outfile):
            outfile.write(self.data.header.kernel_img)
            yield unpacked_md

        if self.data.header_version < 3 or self.is_variant:
            ramdisk_size = self.data.header.ramdisk.size
        else:
            ramdisk_size = len(self.data.header.ramdisk_img)

        if ramdisk_size > 0:
            with meta_directory.unpack_regular_file(pathlib.Path(ramdisk_name)) as (unpacked_md, outfile):
                outfile.write(self.data.header.ramdisk_img)
                yield unpacked_md

        if self.is_variant:
            if self.data.header.second.size > 0:
                with meta_directory.unpack_regular_file(pathlib.Path(secondstage_name)) as (unpacked_md, outfile):
                    outfile.write(self.data.header.second_img)
                    yield unpacked_md

            if self.data.header.dt_size> 0:
                with meta_directory.unpack_regular_file(pathlib.Path(dtb_name)) as (unpacked_md, outfile):
                    outfile.write(self.data.header.dtb)
                    yield unpacked_md
        else:
            if self.data.header_version < 3:
                if self.data.header.second.size > 0:
                    with meta_directory.unpack_regular_file(pathlib.Path(secondstage_name)) as (unpacked_md, outfile):
                        outfile.write(self.data.header.second_img)
                        yield unpacked_md
                if self.data.header_version > 0 and self.data.header.recovery_dtbo.size > 0:
                    with meta_directory.unpack_regular_file(pathlib.Path(recovery_name)) as (unpacked_md, outfile):
                        outfile.write(self.data.header.recovery_dtbo_img)
                        yield unpacked_md
                if self.data.header_version > 1 and self.data.header.dtb.size > 0:
                    with meta_directory.unpack_regular_file(pathlib.Path(dtb_name)) as (unpacked_md, outfile):
                        outfile.write(self.data.header.dtb_img)
                        yield unpacked_md

    @property
    def labels(self):
        labels = ['android', 'android boot image']
        if self.is_variant:
            labels.append('lk variant')
        return labels

    @property
    def metadata(self):
        metadata = {'version': self.data.header_version}
        if self.data.header.name != '':
            metadata['name'] = self.data.header.name
        if self.data.header.cmdline != '':
            metadata['cmdline'] = self.data.header.cmdline
        if not self.is_variant:
            if self.data.header.extra_cmdline != '':
                try:
                    metadata['extra_cmdline'] = self.data.header.extra_cmdline.decode()
                except:
                    pass
            metadata['os_version'] = {'major': self.data.header.os_version.major,
                                     'minor': self.data.header.os_version.minor,
                                     'patch': self.data.header.os_version.patch,
                                     'year': self.data.header.os_version.year,
                                     'month': self.data.header.os_version.month,
                                    }

        return metadata
