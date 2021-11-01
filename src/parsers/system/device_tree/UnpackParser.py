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
from FileResult import FileResult
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError, ValidationGreaterThanError
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
        except (Exception, ValidationNotEqualError, ValidationGreaterThanError) as e:
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

    # check if there are any file image tree images as described
    # here
    # https://elinux.org/images/f/f4/Elc2013_Fernandes.pdf
    def unpack(self, to_meta_directory):
        property_level = 0
        in_kernel = False
        in_fdt = False
        in_ramdisk = False
        has_images = False
        level_to_name = ['']
        is_fit = False
        for node in self.data.structure_block.nodes:
            if node.type == dtb.Dtb.Fdt.begin_node:
                property_level += 1
                if has_images:
                    # TODO: perhaps use "description"?
                    level_to_name.append(node.body.name)
                    if node.body.name.startswith('kernel@'):
                        is_fit = True
                    elif node.body.name.startswith('fdt@'):
                        is_fit = True
                    elif node.body.name.startswith('ramdisk@'):
                        is_fit = True
                if node.body.name == 'images':
                    has_images = True
            elif node.type == dtb.Dtb.Fdt.end_node:
                property_level -= 1
            elif node.type == dtb.Dtb.Fdt.prop:
                if has_images:
                    if node.body.name == 'data':
                        p = pathlib.Path(level_to_name.pop())
                        with to_meta_directory.unpack_regular_file(p) as (unpacked_md, outfile):
                            outfile.write(node.body.property)
                            yield unpacked_md

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.total_size

    labels = ['dtb', 'flattened device tree']
    metadata = {}

