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

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import rockchip


class RockchipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'RKFW'),
        (0, b'RKAF')
    ]
    pretty_name = 'rockchip'

    def parse(self):
        try:
            self.data = rockchip.Rockchip.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = 0

        if self.data.magic == 'RKFW':
            self.unpacked_size = self.data.rockchip.ofs_image + self.data.rockchip.len_image
        elif self.data.magic == 'RKAF':
            # file_size does not include the magic bytes, so add it
            self.unpacked_size = self.data.rockchip.file_size + 4
            for entry in self.data.rockchip.rockchip_files:
                if entry.path == 'SELF':
                    continue
                self.unpacked_size = max(self.unpacked_size, entry.ofs_image + entry.len_image)

        check_condition(self.infile.size >= self.unpacked_size, "not enough data")

    def unpack(self, meta_directory):

        if self.data.magic == 'RKFW':
            entries = self.data.rockchip.rkaf.rockchip_files
        elif self.data.magic == 'RKAF':
            entries = self.data.rockchip.rockchip_files

        seen_paths = set()
        for entry in entries:
            if entry.path == 'SELF':
                continue
            if entry.data is None:
                continue

            out_labels = []

            # This is ugly, but sometimes there are duplicate
            # 'path' entries.
            if entry.path in seen_paths:
                new_name = "%s-%s" % (entry.name, entry.path)
                if new_name in seen_paths:
                    counter = 1
                    while True:
                        name_with_ctr = "%s-renamed-%d" % (new_name, counter)
                        if not new_name in seen_paths:
                            new_name = name_with_ctr
                            out_labels.append('renamed')
                            break
                        counter += 1
                file_path = pathlib.Path(new_name)
            else:
                file_path = pathlib.Path(entry.path)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(entry.data)
                with unpacked_md.open(open_file=False):
                    unpacked_md.info['labels'] = out_labels
                yield unpacked_md
            seen_paths.add(entry.path)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['rockchip']
    metadata = {}
