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

# Android backup files
#
# Description of the format here:
#
# https://nelenkov.blogspot.nl/2012/06/unpacking-android-backups.html
# http://web.archive.org/web/20180425072922/https://nelenkov.blogspot.nl/2012/06/unpacking-android-backups.html
#
# header + zlib compressed data
# zlib compressed data contains a POSIX tar file

import os
import pathlib
import tarfile
import tempfile
import zlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class AndroidBackupUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ANDROID BACKUP\n')
    ]
    pretty_name = 'android_backup'

    def parse(self):
        # only process unencrypted archives
        self.infile.seek(15)

        # check version number
        check_bytes = self.infile.read(2)
        check_condition(check_bytes == b'1\n', "unsupported Android backup version")

        # compression flag
        check_bytes = self.infile.read(2)
        check_condition(check_bytes == b'1\n', "unsupported compression")

        # encryption method
        check_bytes = self.infile.read(5)
        check_condition(check_bytes == b'none\n', "encryption not supported")

        # create a temporary file to write the results to
        # then create a zlib decompression object
        self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
        decompressobj = zlib.decompressobj()

        self.unpacked_size = self.infile.tell()
        self.zlib_start = self.infile.tell()

        # read 1 MB chunks
        chunksize = 1024*1024
        checkbytes = self.infile.read(chunksize)
        try:
            while checkbytes != b'':
                # uncompress the data, and write to an output file
                os.write(self.temporary_file[0], decompressobj.decompress(checkbytes))
                self.unpacked_size += len(checkbytes) - len(decompressobj.unused_data)
                if len(decompressobj.unused_data) != 0:
                    break
                checkbytes = self.infile.read(chunksize)
        except Exception as e:
            os.fdopen(self.temporary_file[0]).close()
            os.unlink(self.temporary_file[1])
            raise UnpackParserException(e.args)
        os.fdopen(self.temporary_file[0]).close()

        # check the if the file is a valid tar file
        try:
            android_tar = tarfile.open(self.temporary_file[1], mode='r')
            members = android_tar.getmembers()
            for member in members:
                pass
        except TarError as e:
            os.unlink(self.temporary_file[1])
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        android_tar = tarfile.open(self.temporary_file[1], mode='r')
        members = android_tar.getmembers()

        for tarinfo in members:
            file_path = pathlib.Path(tarinfo.name)

            if tarinfo.isfile() or tarinfo.issym() or tarinfo.isdir() or tarinfo.islnk():
                try:
                    if tarinfo.isfile(): # normal file
                        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                            tar_reader = android_tar.extractfile(tarinfo)
                            outfile.write(tar_reader.read())
                            yield unpacked_md
                    elif tarinfo.issym(): # symlink
                        target = pathlib.Path(tarinfo.linkname)
                        meta_directory.unpack_symlink(file_path, target)
                    elif tarinfo.islnk(): # hard link
                        target = pathlib.Path(tarinfo.linkname)
                        meta_directory.unpack_hardlink(file_path, target)
                    elif tarinfo.isdir(): # directory
                        meta_directory.unpack_directory(pathlib.Path(tarinfo.name))
                except ValueError:
                    # embedded NUL bytes could cause the extractor to fail
                    continue
            else:
                # block/device characters, sockets, etc. TODO
                pass

        os.unlink(self.temporary_file[1])
            
    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['android', 'androidbackup']
    metadata = {}
