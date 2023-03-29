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
import stat
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class SquashfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'sqsh'),
        (0, b'hsqs'),
        (0, b'shsq'),
        (0, b'qshs'),
        (0, b'tqsh'), # used in DD-WRT
        (0, b'hsqt'), # used in DD-WRT
        (0, b'sqlz')
    ]
    pretty_name = 'squashfs'

    def parse(self):
        # first check if the unpacking tools are available
        self.have_squashfs = True
        if shutil.which('unsquashfs') is None:
            self.have_squashfs = False

        have_sasquahts = True
        if shutil.which('sasquatch') is None:
            self.have_sasquatch = False

        check_condition(self.have_squashfs or self.have_sasquatch,
                        "unsquashfs and sasquatch not found")

        filesize = self.infile.size

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

        squashfs_size = int.from_bytes(checkbytes, byteorder=byteorder)
        check_condition(squashfs_size > 0,
                        "cannot determine size of squashfs file system")

        check_condition(squashfs_size <= filesize,
                        "file system cannot extend past file")

        success = False
        if self.have_squashfs:
            p = subprocess.Popen(['unsquashfs', '-o', str(self.offset), '-lc', self.infile.name],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()
            if p.returncode == 0 or b'because you\'re not superuser!' in errormsg:
                success = True
                self.unpacker = 'unsquashfs'

        if not success:
            p = subprocess.Popen(['sasquatch', '-o', str(self.offset), '-lc', '-p', '1', self.infile.name],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()

            if p.returncode == 0 or b'because you\'re not superuser!' in errormsg:
                success = True
                self.unpacker = 'sasquatch'
        check_condition(success, "invalid or unsupported squashfs file system")

        # by default mksquashfs pads to 4K blocks with NUL bytes.
        # The padding is not counted in squashfs_size
        if squashfs_size % 4096 != 0:
            self.infile.seek(squashfs_size)
            paddingbytes = 4096 - squashfs_size % 4096
            checkbytes = self.infile.read(paddingbytes)
            if len(checkbytes) == paddingbytes:
                if checkbytes == paddingbytes * b'\x00':
                    squashfs_size += paddingbytes

        self.unpacked_size = squashfs_size

    def unpack(self, meta_directory):
        # create a temporary directory and remove it again
        # unsquashfs cannot unpack to an existing directory
        # and move contents after unpacking.
        squashfs_unpack_directory = tempfile.mkdtemp(dir=self.configuration.temporary_directory)
        shutil.rmtree(squashfs_unpack_directory)

        success = False
        if self.unpacker == 'unsquashfs':
            p = subprocess.Popen(['unsquashfs', '-o', str(self.offset), '-d', squashfs_unpack_directory, self.infile.name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()
            if p.returncode == 0 or b'because you\'re not superuser!' in errormsg:
                success = True
        else:
            p = subprocess.Popen(['sasquatch', '-o', str(self.offset), '-p', '1', '-d', squashfs_unpack_directory, self.infile.name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()

        # move the unpacked files
        # move contents of the unpacked file system
        for result in pathlib.Path(squashfs_unpack_directory).glob('**/*'):
            file_path = result.relative_to(squashfs_unpack_directory)

            if result.is_symlink():
                meta_directory.unpack_symlink(file_path, result.readlink())
            elif result.is_dir():
                result.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                meta_directory.unpack_directory(file_path)
            elif result.is_file():
                result.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                with meta_directory.unpack_regular_file_no_open(file_path) as (unpacked_md, outfile):
                    self.local_copy2(result, outfile)
                    yield unpacked_md
            else:
                continue

        # clean up the temporary directory
        shutil.rmtree(squashfs_unpack_directory)

    # a wrapper around shutil.copy2 to copy symbolic links instead of
    # following them and copying the data.
    def local_copy2(self, src, dest):
        '''Wrapper around shutil.copy2 for squashfs unpacking'''
        return shutil.copy2(src, dest, follow_symlinks=False)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['squashfs', 'filesystem']

    @property
    def metadata(self):
        metadata = {}
        metadata['unpacker'] = self.unpacker
        return metadata
