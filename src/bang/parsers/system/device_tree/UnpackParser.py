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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import dtb

class DeviceTreeUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xd0\x0d\xfe\xed')
    ]
    pretty_name = 'dtb'

    def parse(self):
        try:
            self.data = dtb.Dtb.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.infile.size >= self.data.total_size, "not enough data")
        if self.data.version > 16:
            check_condition(self.data.min_compatible_version, "invalid compatible version")

        # check some offsets
        check_condition(self.data.ofs_memory_reservation_block > 36,
                        "invalid offset for memory reservation block")
        check_condition(self.data.ofs_structure_block > self.data.ofs_memory_reservation_block,
                        "invalid offset for structure block")
        check_condition(self.data.ofs_strings_block > self.data.ofs_structure_block,
                        "invalid offset for strings block")
        check_condition(self.data.ofs_structure_block + self.data.len_structure_block <= self.data.total_size,
                        "invalid offset/size for structure block")
        check_condition(self.data.ofs_strings_block + self.data.len_strings_block <= self.data.total_size,
                        "invalid offset/size for strings block")

        # sanity check: the fdt nodes are actually a tree, not a list
        property_level = 0
        for node in self.data.structure_block.nodes:
            if node.type == dtb.Dtb.Fdt.begin_node:
                property_level += 1
            elif node.type == dtb.Dtb.Fdt.end_node:
                check_condition(property_level > 0, "invalid fdt tree")
                property_level -= 1
            elif node.type == dtb.Dtb.Fdt.end:
                check_condition(property_level == 0, "invalid fdt tree")

        # Some dtb images are so called "file image tree" (FIT) images.
        #
        # https://elinux.org/images/f/f4/Elc2013_Fernandes.pdf
        #
        # These either contain the data inside the dtb, but there are also some
        # FIT images where data is not in the dtb, but appended to the dtb and
        # only offsets (either relative or absolute) and sizes are recorded
        # instead of the actual data.
        #
        # Reference: https://source.denx.de/u-boot/u-boot/-/commit/529fd1886639e5348a6f430d931eedd05c4cc93e
        in_images = False
        property_level = 0
        images_level = 0
        image_name = ''

        self.images = {}

        number_of_padding_bytes = 0
        if self.data.total_size % 4 != 0:
            number_of_padding_bytes = 4 - (self.data.total_size % 4)

        for node in self.data.structure_block.nodes:
            if node.type == dtb.Dtb.Fdt.begin_node:
                property_level += 1
                if node.body.name == 'images':
                    in_images = True
                    images_level = property_level
                else:
                    if property_level <= images_level:
                        in_images = False
                if in_images:
                    if property_level == images_level + 1 and image_name == '':
                        image_name = node.body.name
                        self.images[image_name] = {}
                    else:
                        image_name = ''
            elif node.type == dtb.Dtb.Fdt.end_node:
                property_level -= 1
            elif node.type == dtb.Dtb.Fdt.prop:
                if in_images and image_name != '':
                    if node.body.name == 'data-offset':
                        data_offset = int.from_bytes(node.body.property, byteorder='big')
                        self.images[image_name]['offset'] = data_offset
                        self.images[image_name]['abs_offset'] = data_offset + number_of_padding_bytes + self.data.total_size
                    elif node.body.name == 'data-position':
                        data_offset = int.from_bytes(node.body.property, byteorder='big')
                        self.images[image_name]['abs_offset'] = data_offset
                    elif node.body.name == 'data-size':
                        data_size = int.from_bytes(node.body.property, byteorder='big')
                        self.images[image_name]['size'] = data_size

        self.unpacked_size = self.data.total_size

        # check the images that have data outside of the dtb
        remove = []
        for image in self.images:
            if self.images[image] != {}:
                check_condition(self.images[image]['abs_offset'] + self.images[image]['size'] <= self.infile.size,
                                "FIT image outside of file")
                self.unpacked_size = max(self.unpacked_size, self.images[image]['abs_offset'] + self.images[image]['size'])
            else:
                remove.append(image)

        # remove images that have the data in the dtb from the list
        for r in remove:
            del self.images[r]

    def unpack(self, to_meta_directory):
        property_level = 0
        in_kernel = False
        in_fdt = False
        in_ramdisk = False
        has_images = False
        level_to_name = ['']
        self.is_fit = False

        # walk the nodes and write data for FIT images
        if self.images != {}:
            for image in self.images:
                file_path = pathlib.Path(image)
                with to_meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    os.sendfile(outfile.fileno(), self.infile.fileno(), self.offset + self.images[image]['abs_offset'], self.images[image]['size'])
                    yield unpacked_md
        else:
            for node in self.data.structure_block.nodes:
                if node.type == dtb.Dtb.Fdt.begin_node:
                    property_level += 1
                    if has_images:
                        level_to_name.append(node.body.name)
                        if node.body.name.startswith('kernel@'):
                            self.is_fit = True
                        elif node.body.name.startswith('fdt@'):
                            self.is_fit = True
                        elif node.body.name.startswith('ramdisk@'):
                            self.is_fit = True
                    if node.body.name == 'images':
                        has_images = True
                elif node.type == dtb.Dtb.Fdt.end_node:
                    property_level -= 1
                elif node.type == dtb.Dtb.Fdt.prop:
                    if has_images:
                        if node.body.name == 'data':
                            file_path = pathlib.Path(level_to_name.pop())
                            with to_meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                                outfile.write(node.body.property)
                                yield unpacked_md

    def calculate_unpacked_size(self):
        pass

    labels = ['dtb', 'flattened device tree']
    metadata = {}
