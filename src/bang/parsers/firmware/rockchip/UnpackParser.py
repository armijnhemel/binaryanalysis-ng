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
            raise UnpackParserException(e.args) from e

        self.unpacked_size = 0

        if self.data.magic == 'RKFW':
            self.unpacked_size = self.data.rockchip.ofs_image + self.data.rockchip.len_image
            self.rockchip_type = 'rkfw'
        elif self.data.magic == 'RKAF':
            # file_size does not include the magic bytes, so add it
            self.unpacked_size = self.data.rockchip.file_size + 4
            for entry in self.data.rockchip.rockchip_files:
                if entry.path == 'SELF':
                    continue
                self.unpacked_size = max(self.unpacked_size, entry.ofs_image + entry.len_image)
            self.rockchip_type = 'rkaf'

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
                new_name = f"{entry.name}-{entry.path}"
                if new_name in seen_paths:
                    counter = 1
                    while True:
                        name_with_ctr = f"{new_name}-renamed-{counter}"
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

    @property
    def metadata(self):
        metadata = {}
        metadata['type'] = self.rockchip_type
        if self.rockchip_type == 'rkfw':
            # TODO: record more info about chipset, etc.
            pass
        return metadata
