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

# https://www.coreboot.org/CBFS
# test files: https://rsync.libreboot.org/testing/

class CbfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'LARCHIVE')
    ]
    pretty_name = 'cbfs'

    def open(self):
        # parsing CBFS is a bit more difficult because the identifier
        # is not at a fixed offset in the file but there could be (valid)
        # data before the first header.
        # This is why the wrapped file (with the artificial offset) cannot
        # be used.
        filename_full = self.scan_environment.get_unpack_path_for_fileresult(
                    self.fileresult)
        f = filename_full.open('rb')
        self.infile = f

    def parse(self):
        # seek to the offset
        self.infile.seek(self.offset)

        # what follows is a list of components
        havecbfscomponents = False

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

            # length
            buf = self.infile.read(4)
            check_condition(len(buf) == 4, "not enough data for length field")
            component_length = int.from_bytes(buf, byteorder='big')

            # type
            buf = self.infile.read(4)
            check_condition(len(buf) == 4, "not enough data for type field")
            component_type = int.from_bytes(buf, byteorder='big')

            # checksum
            buf = self.infile.read(4)
            check_condition(len(buf) == 4, "not enough data for checksum field")
            checksum = int.from_bytes(buf, byteorder='big')

            # component offset
            buf = self.infile.read(4)
            check_condition(len(buf) == 4, "not enough data for component offset field")
            component_offset = int.from_bytes(buf, byteorder='big')

            # "The difference between the size of the header and offset
            # is the size of the component name."
            name_length = component_offset - 24
            buf = self.infile.read(name_length)
            check_condition(len(buf) == name_length,
                            "not enough data for component name field")
            if b'\x00' not in buf:
                raise UnpackParserException("invalid component name, not NULL terminated")

            try:
                component_name = buf.split(b'\x00')[0].decode()
            except Exception as e:
                raise UnpackParserException(e.args)

            end_of_component = self.infile.tell() + component_length
            self.maxsize = max(self.maxsize, end_of_component)
            check_condition(end_of_component <= self.fileresult.filesize, "data outside of file")

            # store the current offset
            curoffset = self.infile.tell()

            self.offsets[self.infile.tell()] = (component_length, component_name)

            # read the first four bytes of the payload to see
            # if this is the master header
            buf = self.infile.read(4)
            check_condition(len(buf) == 4, "not enough data for payload magic")
            if buf == b'ORBC':
                check_condition(not seen_master_header, "only one master header allowed")

                # version
                buf = self.infile.read(4)
                check_condition(len(buf) == 4, "not enough data for master version field")
                master_version = int.from_bytes(buf, byteorder='big')

                # romsize
                buf = self.infile.read(4)
                check_condition(len(buf) == 4, "not enough data for romsize field")
                self.romsize = int.from_bytes(buf, byteorder='big')

                # check if the rom size isn't larger than the actual file.
                # As the master header won't be at the beginning of the file
                # the check should be against size of the entire file, not
                # starting at the offset, unless that is already part
                # of another file (TODO).
                check_condition(self.romsize <= self.fileresult.filesize,
                                "not enough data for image")

                # boot block size
                buf = self.infile.read(4)
                check_condition(len(buf) == 4, "not enough data for boot block size field")
                boot_block_size = int.from_bytes(buf, byteorder='big')
                check_condition(boot_block_size <= self.romsize, "invalid boot block size")

                # align, always 64 bytes
                buf = self.infile.read(4)
                check_condition(len(buf) == 4, "not enough data for align field")
                align = int.from_bytes(buf, byteorder='big')
                check_condition(align == 64, "invalid alignment size")
                check_condition(self.romsize >= align, "invalid rom size")

                # offset of first block
                buf = self.infile.read(4)
                check_condition(len(buf) == 4, "not enough data for cbfs offset field")
                cbfs_offset = int.from_bytes(buf, byteorder='big')
                check_condition(cbfs_offset <= self.romsize,
                                "offset of first block cannot be outside image")

                check_condition(cbfs_offset <= self.offset,
                                "invalid first block offset")

                # architecture
                buf = self.infile.read(4)
                check_condition(len(buf) == 4, "not enough data for architecture field")
                architecture = int.from_bytes(buf, byteorder='big')

                # padding
                buf = self.infile.read(4)
                check_condition(len(buf) == 4, "not enough data for padding field")
                seen_master_header = True

            # assume for now that the first block encountered
            # is always the master header
            check_condition(seen_master_header, "no master header found")

            self.infile.seek(curoffset)
            self.infile.seek(component_length, os.SEEK_CUR)

            # skip alignment bytes
            if self.infile.tell() % align != 0:
                self.infile.seek(align - (self.infile.tell() % align), os.SEEK_CUR)
        check_condition(seen_master_header, "no master header found")
        check_condition(self.romsize <= self.maxsize, "invalid rom size")
        self.offset = self.maxsize - self.romsize


    def unpack(self):
        unpacked_files = []
        for component_offset in self.offsets:
            length, name = self.offsets[component_offset]
            if name == '':
                continue

            outfile_rel = self.rel_unpack_dir / name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)

            self.infile.seek(component_offset)
            outfile = open(outfile_full, 'wb')
            outfile.write(self.infile.read(length))
            outfile.close()
            fr = FileResult(self.fileresult, outfile_rel, set([]))
            unpacked_files.append(fr)
        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    def calculate_unpacked_size(self):
        self.unpacked_size = self.romsize

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['coreboot']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
