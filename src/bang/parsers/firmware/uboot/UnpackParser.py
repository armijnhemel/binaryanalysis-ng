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

import binascii
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import uimage


class UbootUnpackParser(UnpackParser):
    extensions = []

    # There are different U-Boot files with different magic,
    # see uimage.ksy for documentation
    signatures = [
        (0, b'\x00\x00\x00\x05'),
        (0, b'\x00\x00\x00\x06'),
        (0, b'\x00\x00\x00\x16'),
        (0, b'\x00\x70\x34\x00'),
        (0, b'\x00\x90\x40\x00'),
        (0, b'\x03\x01\x05\x00'),
        (0, b'\x03\x01\x13\x00'),
        (0, b'\x03\x01\x13\x02'),
        (0, b'\x03\x01\x24\x01'),
        (0, b'\x03\x01\x31\x00'),
        (0, b'\x03\x11\x11\x00'),
        (0, b'\x03\x11\x13\x00'),
        (0, b'\x03\x80\x29\x10'),
        (0, b'\x03\x80\x59\x12'),
        (0, b'\x03\x80\x79\x28'),
        (0, b'\x03\x87\x20\x10'),
        (0, b'\x03\x87\x20\x28'),
        (0, b'\x03\x87\x92\x8f'),
        (0, b'\x03\x97\x20\x52'),
        (0, b'\x03\x97\x95\x2f'),
        (0, b'\x12\x29\x10\x00'),
        (0, b'\x12\x34\x50\x00'),
        (0, b'\x17\x4e\x47\x41'),
        (0, b'\x17\x4e\x47\x42'),
        (0, b'\x26\x11\x20\x15'),
        (0, b'\x27\x05\x19\x56'),
        (0, b'\x27\x05\x19\x67'),
        (0, b'\x30\x36\x31\x32'),
        (0, b'\x31\x30\x30\x30'),
        (0, b'\x31\x30\x30\x31'),
        (0, b'\x31\x30\x30\x32'),
        (0, b'\x31\x30\x30\x34'),
        (0, b'\x31\x31\x30\x30'),
        (0, b'\x31\x50\x41\x57'),
        (0, b'\x32\x30\x30\x31'),
        (0, b'\x32\x30\x30\x33'),
        (0, b'\x32\x30\x30\x34'),
        (0, b'\x32\x30\x36\x31'),
        (0, b'\x32\x32\x30\x30'),
        (0, b'\x33\x37\x30\x30'),
        (0, b'\x33\x37\x30\x31'),
        (0, b'\x33\x37\x30\x33'),
        (0, b'\x36\x30\x30\x30'),
        (0, b'\x36\x31\x32\x32'),
        (0, b'\x43\x4f\x4d\x42'),
        (0, b'\x43\x4f\x4d\x43'),
        (0, b'\x4e\x47\x43\x35'),
        (0, b'\x4e\x47\x45\x20'),
        (0, b'\x4e\x47\x46\x20'),
        (0, b'\x4e\x47\x47\x20'),
        (0, b'\x4e\x47\x48\x20'),
        (0, b'\x4e\x47\x49\x20'),
        (0, b'\x4e\x47\x50\x20'),
        (0, b'\x4f\x4b\x4c\x49'),
        (0, b'\x68\x73\x71\x73'),
        (0, b'\x73\x71\x4f\x4b'),
        (0, b'\x80\x80\x00\x02'),
        (0, b'\x80\x80\x00\x03'),
        (0, b'\x83\x01\x13\x00'),
        (0, b'\x83\x01\x13\x02'),
        (0, b'\x83\x01\x24\x01'),
        (0, b'\x83\x80\x00\x00'),
        (0, b'\x83\x80\x00\x01'),
        (0, b'\x83\x80\x00\x02'),
        (0, b'\x83\x80\x00\x03'),
        (0, b'\x83\x80\x00\x04'),
        (0, b'\x83\x80\x00\x10'),
        (0, b'\x83\x80\x00\x11'),
        (0, b'\x83\x80\x00\x12'),
        (0, b'\x83\x80\x00\x13'),
        (0, b'\x83\x80\x1a\x0d'),
        (0, b'\x83\x80\x1a\x0e'),
        (0, b'\x83\x80\x21\x08'),
        (0, b'\x83\x80\x21\x10'),
        (0, b'\x83\x80\x29\x10'),
        (0, b'\x83\x80\x51\x10'),
        (0, b'\x83\x80\x52\x12'),
        (0, b'\x83\x80\x59\x12'),
        (0, b'\x83\x80\x79\x28'),
        (0, b'\x83\x87\x20\x10'),
        (0, b'\x83\x87\x20\x28'),
        (0, b'\x83\x87\x22\x8f'),
        (0, b'\x83\x87\x92\x8f'),
        (0, b'\x83\x90\x00\x00'),
        (0, b'\x83\x96\x00\x00'),
        (0, b'\x83\x97\x20\x52'),
        (0, b'\x83\x97\x25\x2f'),
        (0, b'\x83\x97\x95\x2f'),
        (0, b'\x93\x00\x00\x00'),
        (0, b'\x93\x00\x10\x10'),
        (0, b'\x93\x00\x12\x10'),
        (0, b'\x93\x00\x12\x50'),
        (0, b'\x93\x03\x00\x00'),
        (0, b'\x93\x10\x00\x00'),
    ]
    pretty_name = 'uboot'

    def parse(self):
        try:
            self.data = uimage.Uimage.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

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
        if self.data.header.name_or_asus_info.has_asus_info:
            try:
                asus_product_id = self.data.header.name_or_asus_info.asus_info.product_id
                for family in asus_product_families:
                    if asus_product_id.startswith(family):
                        self.is_asus_device = True
                        break
            except:
                pass

    def unpack(self, meta_directory):
        # set the name of the image. If the name of the image is
        # an empty string hardcode a name based
        # on the image type of the U-Boot file.
        #
        # TODO: correctly process multi images

        if self.is_asus_device or self.data.header.name_or_asus_info.name == '' or not self.data.header.name_or_asus_info.name.isprintable():
            imagename = self.data.header.image_type.name
        else:
            imagename = self.data.header.name_or_asus_info.name

        file_path = pathlib.Path(imagename)
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.data)
            yield unpacked_md

    @property
    def labels(self):
        labels = ['u-boot']
        if self.is_asus_device:
            labels.append('asus')
        return labels

    @property
    def metadata(self):
        metadata = {
            'header_crc': self.data.header.header_crc,
            'timestamp': self.data.header.timestamp,
            'load_address': self.data.header.load_address,
            'entry_point_address': self.data.header.entry_address,
            'image_data_crc': self.data.header.data_crc,
            'os': self.data.header.os_type.name,
            'architecture': self.data.header.architecture.name,
            'image_type': self.data.header.image_type.name
        }

        if self.is_asus_device:
            asus_product_id = self.data.header.name_or_asus_info.asus_info.product_id
            metadata['vendor'] = 'ASUS'
            metadata['product_id'] = asus_product_id
        return metadata
