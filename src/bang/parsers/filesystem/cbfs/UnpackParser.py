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

from bang.UnpackParser import UnpackParser, check_condition, OffsetInputFile
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import cbfs

# https://www.coreboot.org/CBFS
# test files: https://rsync.libreboot.org/testing/


class CbfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'LARCHIVE')
    ]
    pretty_name = 'cbfs'

    def __init__(self, from_meta_directory, offset, configuration):
        self.md = from_meta_directory
        self.offset = offset

        # set the artificial offset to 0
        self.infile = OffsetInputFile(from_meta_directory, 0)

    def parse(self):
        # seek to the offset where the first component is found
        self.infile.seek(self.offset)

        # there should be one master header, which defines a
        # few characteristics, such as the byte alignment. This
        # one should come first to be able to read the rest.
        seen_master_header = False

        # offsets, names and sizes of the individual partitions/components
        self.offsets = {}

        self.maxsize = 0

        # It is assumed that the first block encountered is the master header
        while True:
            buf = self.infile.read(8)
            if buf != b'LARCHIVE':
                break

            # rewind
            self.infile.seek(-8, os.SEEK_CUR)
            start_offset = self.infile.tell()

            try:
                component = cbfs.Cbfs.Component.from_io(self.infile)
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)

            end_of_component = self.infile.tell()

            self.maxsize = max(self.maxsize, end_of_component)

            self.offsets[start_offset + component.header.offset] = (component.header.len_data, component.name)

            # read the first four bytes of the payload to see
            # if this is the master header
            buf = component.data[:4]
            if buf == b'ORBC':
                check_condition(not seen_master_header, "only one master header allowed")

                # parse the header with kaitai struct
                try:
                    master_header = cbfs.Cbfs.Header.from_bytes(component.data)
                except (Exception, ValidationFailedError) as e:
                    raise UnpackParserException(e.args)

                # romsize
                self.romsize = master_header.len_rom
                check_condition(self.romsize >= master_header.align, "invalid rom size")

                # check if the rom size isn't larger than the actual file.
                # As the master header won't be at the beginning of the file
                # the check should be against size of the entire file, not
                # starting at the offset, unless that is already part
                # of another file (TODO).
                check_condition(self.romsize <= self.infile.size,
                                "not enough data for image")

                # boot block size
                check_condition(master_header.len_boot_block <= self.romsize, "invalid boot block size")

                # offset of first block
                check_condition(master_header.cbfs_offset <= self.romsize,
                                "offset of first block cannot be outside image")

                check_condition(master_header.cbfs_offset <= self.offset,
                                "invalid first block offset")

                seen_master_header = True

            # assume for now that the first block encountered
            # is always the master header
            check_condition(seen_master_header, "no master header found")

            # skip alignment bytes
            if self.infile.tell() % master_header.align != 0:
                self.infile.seek(master_header.align - (self.infile.tell() % master_header.align), os.SEEK_CUR)

        check_condition(seen_master_header, "no master header found")
        check_condition(self.romsize <= self.maxsize, "invalid rom size")
        self.offset = self.maxsize - self.romsize

    def unpack(self, meta_directory):
        unpacked_files = []
        for component_offset in self.offsets:
            length, name = self.offsets[component_offset]
            if name == '':
                continue

            file_path = pathlib.Path(name)

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                self.infile.seek(component_offset)
                outfile.write(self.infile.read(length))
                yield unpacked_md

    def calculate_unpacked_size(self):
        self.unpacked_size = self.romsize

    labels = ['coreboot']
    metadata = {}
