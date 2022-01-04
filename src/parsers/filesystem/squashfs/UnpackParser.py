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

# Squashfs is a read only file system

import os
import pathlib
import shutil
import subprocess

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_squashfs

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class SquashfsUnpackParser(WrappedUnpackParser):
#class SquashfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'sqsh'),
        (0, b'hsqs'),
        (0, b'shsq'),
        (0, b'qshs'),
        (0, b'tqsh'),
        (0, b'hsqt'),
        (0, b'sqlz')
    ]
    pretty_name = 'squashfs'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_squashfs(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        # first check if the unpacking tools are available
        have_squashfs = True
        if shutil.which('unsquashfs') is None:
            have_squashfs = False

        have_sasquahts = True
        if shutil.which('sasquatch') is None:
            have_sasquahts = False

        check_condition(have_squashfs or have_sasquatch,
                        "unsquashfs and sasquatch not found")

        filesize = self.fileresult.filesize

        # The squashfs header and version is 30 bytes
        # need at least a header, plus version
        # according to /usr/share/magic
        check_condition(filesize - self.offset >= 30,
                        "not enough data for squashfs header")

        self.infile.seek(0)

        little_endian_signatures = [b'hsqs', b'shsq', b'hsqt']

        # sanity checks for the squashfs header.
        # First determine the endianness of the file system.
        checkbytes = self.infile.read(4)
        if checkbytes in little_endian_signatures:
            bigendian = False
            byteorder = 'little'
        else:
            bigendian = True
            byteorder = 'big'

        # then skip to the version, as this is an effective way to filter
        # false positives.
        self.infile.seek(28)
        checkbytes = self.infile.read(2)
        self.major_version = int.from_bytes(checkbytes, byteorder=byteorder)

        # So far only squashfs 1-4 have been released (June 2018)
        check_condition(self.major_version > 0 and self.major_version < 5,
                        "invalid squashfs version")

        # The location of the size of the squashfs file system depends
        # on the major version of the file. These values can be found in
        # /usr/share/magic or in the squashfs-tools source code
        # ( squashfs_compat.h and squashfs_fs.h )
        if self.major_version == 4:
            self.infile.seek(40)
            checkbytes = self.infile.read(8)
            check_condition(len(checkbytes) == 8,
                            "not enough data to read squashfs size")
        elif self.major_version == 3:
            self.infile.seek(63)
            checkbytes = self.infile.read(8)
            check_condition(len(checkbytes) == 8,
                            "not enough data to read squashfs size")
        elif self.major_version in [1, 2]:
            self.infile.seek(8)
            checkbytes = self.infile.read(4)
            check_condition(len(checkbytes) == 4,
                            "not enough data to read squashfs size")

        squashfssize = int.from_bytes(checkbytes, byteorder=byteorder)
        check_condition(squashfssize > 0,
                        "cannot determine size of squashfs file system")

        check_condition(self.offset + squashfssize <= filesize,
                        "file system cannot extend past file")

        # write the data to a temporary file if the offset != 0
        # and run unsquashfs or sasquatch
        if self.offset != 0:
            check_condition(self.offset == 0, "only offset 0 supported now")

        success = False
        if have_squashfs:
            p = subprocess.Popen(['unsquashfs', '-lc', self.infile.name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()
            if p.returncode == 0 or b'because you\'re not superuser!' in errormsg:
                success = True

        if not success:
            p = subprocess.Popen(['sasquatch', '-lc', '-p', '1', self.infile.name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()

            if p.returncode == 0 or b'because you\'re not superuser!' in errormsg:
                success = True
        check_condition(success, "invalid or unsupported squashfs file system")

        # by default mksquashfs pads to 4K blocks with NUL bytes.
        # The padding is not counted in squashfssize
        if squashfssize % 4096 != 0:
            self.infile.seek(squashfssize)
            paddingbytes = 4096 - squashfssize % 4096
            checkbytes = self.infile.read(paddingbytes)
            if len(checkbytes) == paddingbytes:
                if checkbytes == paddingbytes * b'\x00':
                    squashfssize += paddingbytes

        self.unpacked_size = squashfssize

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['squashfs', 'filesystem']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
