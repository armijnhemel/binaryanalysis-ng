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
import pathlib

from FileResult import FileResult
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import uimage


class UbootLegacyUnpackParser(UnpackParser):
    extensions = []

    # There are different U-Boot files with different magic:
    # - regular U-Boot
    # - .bix as apparently used by ZyXEL and Cisco in some devices
    signatures = [
        (0, b'\x27\x05\x19\x56'),
        (0, b'\x80\x80\x00\x02'),
        (0, b'\x83\x80\x00\x00'),
        (0, b'\x93\x00\x00\x00')
    ]
    pretty_name = 'uboot_legacy'

    def parse(self):
        try:
            self.data = uimage.Uimage.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # now calculate the CRC of the header and compare it
        # to the stored one
        oldoffset = self.infile.infile.tell()
        self.infile.infile.seek(self.infile.offset)
        crcbytes = bytearray(64)
        self.infile.infile.readinto(crcbytes)
        crcmv = memoryview(crcbytes)

        # blank the header CRC field first
        crcmv[4:8] = b'\x00' * 4
        header_crc = binascii.crc32(crcmv)
        crcmv.release()
        self.infile.infile.seek(oldoffset)

        check_condition(header_crc == self.data.header.header_crc, "invalid header CRC")

        # image data crc
        data_crc = binascii.crc32(self.data.data)
        check_condition(data_crc == self.data.header.data_crc, "invalid image data CRC")

        # First try to see if this is perhaps an ASUS device
        self.is_asus_device = False
        asus_product_families = ['4G-', 'BRT-', 'GS-', 'GT-', 'PL-', 'RP-', 'RT-']
        try:
            asus_product_id = self.data.header.asus_info.product_id
            for family in asus_product_families:
                if asus_product_id.startswith(family):
                    self.is_asus_device = True
                    break
        except:
            pass

    def unpack(self):
        unpacked_files = []
        # set the name of the image. If the name of the image is
        # an empty string hardcode a name based
        # on the image type of the U-Boot file.


        if self.is_asus_device or self.data.header.name == '':
            imagename = self.data.header.image_type.name
        else:
            imagename = self.data.header.name

        outfile_rel = self.rel_unpack_dir / imagename
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.data.data)
        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / imagename, set())
        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['u-boot']

        metadata = {}
        metadata['header_crc'] = self.data.header.header_crc
        metadata['timestamp'] = self.data.header.timestamp
        metadata['load_address'] = self.data.header.load_address
        metadata['entry_point_address'] = self.data.header.entry_address
        metadata['image_data_crc'] = self.data.header.data_crc
        metadata['os'] = self.data.header.os_type.name
        metadata['architecture'] = self.data.header.architecture.name
        metadata['image_type'] = self.data.header.image_type.name

        if self.is_asus_device:
            labels.append('asus')
            asus_product_id = self.data.header.asus_info.product_id
            metadata['vendor'] = 'ASUS'
            metadata['product_id'] = asus_product_id

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
