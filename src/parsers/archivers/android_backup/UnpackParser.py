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

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

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
        temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
        decompressobj = zlib.decompressobj()

        self.unpacked_size = self.infile.tell()
        self.zlib_start = self.infile.tell()

        # read 1 MB chunks
        chunksize = 1024*1024
        checkbytes = self.infile.read(chunksize)
        try:
            while checkbytes != b'':
                # uncompress the data, and write to an output file
                os.write(temporary_file[0], decompressobj.decompress(checkbytes))
                self.unpacked_size += len(checkbytes) - len(decompressobj.unused_data)
                if len(decompressobj.unused_data) != 0:
                    break
                checkbytes = self.infile.read(chunksize)
        except Exception as e:
            os.fdopen(temporary_file[0]).close()
            os.unlink(temporary_file[1])
            raise UnpackParserException(e.args)
        os.fdopen(temporary_file[0]).close()

        # check the if the file is a valid tar file
        try:
            android_tar = tarfile.open(temporary_file[1], mode='r')
            members = android_tar.getmembers()
            for member in members:
                pass
        except TarError as e:
            raise UnpackParserException(e.args)
        finally:
            os.unlink(temporary_file[1])

    def unpack(self):
        unpacked_files = []

        temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
        decompressobj = zlib.decompressobj()
        self.infile.seek(self.zlib_start)

        # read 1 MB chunks
        chunksize = 1024*1024
        checkbytes = self.infile.read(chunksize)
        while checkbytes != b'':
            # uncompress the data, and write to an output file
            os.write(temporary_file[0], decompressobj.decompress(checkbytes))
            self.unpacked_size += len(checkbytes) - len(decompressobj.unused_data)
            if len(decompressobj.unused_data) != 0:
                break
            checkbytes = self.infile.read(chunksize)
        os.fdopen(temporary_file[0]).close()

        android_tar = tarfile.open(temporary_file[1], mode='r')
        members = android_tar.getmembers()

        for entry in members:
            out_labels = []
            file_path = pathlib.Path(entry.name)

            if file_path.is_absolute():
                file_path = pathlib.Path(entry.name).relative_to('/')
                entry.name = file_path
            android_tar.extract(entry.name, path=self.rel_unpack_dir)

            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        os.unlink(temporary_file[1])
        return unpacked_files
            
    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    # no need to carve from the file
    def carve(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'androidbackup']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
