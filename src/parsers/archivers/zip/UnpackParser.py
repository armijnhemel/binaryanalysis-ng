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

'''
ZIP specifications can be found at:

https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
(latest version: version 6.3.8)

This parser first verifies a file to see where the ZIP data
starts and where it ends.

Python's zipfile module starts looking at the end of the file
for a central directory. If multiple ZIP files have been concatenated
and the last ZIP file is at the end, then only this ZIP file
will be unpacked by Python's zipfile module.

A description of some of the underlying problems encountered
when writing this code can be found here:

http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html
'''

import os
import pathlib

import pyaxmlparser

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_zip

MIN_VERSION = 0
MAX_VERSION = 90

# several ZIP headers
ARCHIVE_EXTRA_DATA = b'\x50\x4b\x06\x08'
CENTRAL_DIRECTORY = b'\x50\x4b\x01\02'
DIGITAL_SIGNATURE = b'\x50\x4b\x05\x05'
END_OF_CENTRAL_DIRECTORY = b'\x50\x4b\x05\x06'
LOCAL_FILE_HEADER = b'\x50\x4b\x03\x04'
ZIP64_END_OF_CENTRAL_DIRECTORY = b'\x50\x4b\x06\x06'
ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR = b'\x50\x4b\x06\x07'

#class ZipUnpackParser(WrappedUnpackParser):
class ZipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x50\x4b\x03\04'),
        # http://web.archive.org/web/20190709133846/https://ipcamtalk.com/threads/dahua-ipc-easy-unbricking-recovery-over-tftp.17189/page-2
        #(0, b'DH\x03\04')
    ]
    pretty_name = 'zip'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zip(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        self.encrypted = False
        self.zip64 = False

        # store if there is an Android signing block:
        # https://source.android.com/security/apksigning/v2
        self.android_signing = False

        # First there are file entries, followed by a central
        # directory, possibly with other headers following/preceding
        # store the local file names to check if they appear in the
        # central directory in the same order (optional)
        local_files = []
        central_directory_files = []

        seen_central_directory = False
        in_local_entry = True
        seen_zip64_end_of_central_dir = False

        seen_first_header = False

        while True:
            # first read the header
            checkbytes = self.infile.read(4)
            check_condition(len(checkbytes) == 4,
                            "not enough data for ZIP entry header")

            # process everything that is not a local file header, but
            # either a ZIP header or an Android signing signature.
            if checkbytes != LOCAL_FILE_HEADER:
                in_local_entry = False

                # check the different file headers
                # archive decryption header
                # archive extra data field (section 4.3.11)
                if checkbytes == ARCHIVE_EXTRA_DATA:
                    checkbytes = self.infile.read(4)
                    check_condition(len(checkbytes) == 4,
                                    "not enough data for archive decryption header field")

                    archive_decryption_size = int.from_bytes(checkbytes, byteorder='little')
                    check_condition(self.infile.tell() + archive_decryption_size <= self.fileresult.filesize,
                                    "not enough data for archive decryption header field")

                    # skip the archive data
                    self.infile.seek(archive_decryption_size, os.SEEK_CUR)
            elif checkbytes == CENTRAL_DIRECTORY:
                # check for the start of the central directory (section 4.3.12)
                seen_central_directory = True

                # the central directory is 46 bytes minimum
                check_condition(self.infile.tell() + 46 <= self.fileresult.filesize,
                                "not enough data for central directory")

                # skip 24 bytes in the header to the file name
                # and extra field
                self.infile.seek(24, os.SEEK_CUR)

                # read the file name
                checkbytes = self.infile.read(2)
                len_filename = int.from_bytes(checkbytes, byteorder='little')

                # read the extra field length
                checkbytes = self.infile.read(2)
                len_extra_field = int.from_bytes(checkbytes, byteorder='little')

                # read the file comment length
                checkbytes = self.infile.read(2)
                len_file_comment = int.from_bytes(checkbytes, byteorder='little')

                # skip 12 bytes in the central directory header to the file name
                self.infile.seek(12, os.SEEK_CUR)

                # read the file name
                checkbytes = self.infile.read(len_filename)
                check_condition(len(checkbytes) == len_filename,
                                "not enough data for file name in central directory")

                # store the file name (as byte string)
                central_directory_files.append(checkbytes)

                if len_extra_field != 0:
                    # read the extra field
                    checkbytes = self.infile.read(len_extra_field)
                    check_condition(len(checkbytes) == len_extra_field,
                                "not enough data for extra field in central directory")

                if len_file_comment != 0:
                    # read the file comment
                    checkbytes = self.infile.read(len_file_comment)
                    check_condition(len(checkbytes) == len_file_comment,
                                "not enough data for file comment in central directory")
            elif checkbytes == DIGITAL_SIGNATURE:
                # check for digital signatures (section 4.3.13)
                checkbytes = self.infile.read(2)
                check_condition(len(checkbytes) == 2,
                                "not enough data for digital signature size field")

                # read the length of the digital signature
                len_digital_signature = int.from_bytes(checkbytes, byteorder='little')
                check_condition(self.infile.tell() + len_digital_signature <= self.fileresult.filesize,
                                "not enough data for digital signature")

                # skip the digital signature data
                self.infile.seek(len_digital_signature, os.SEEK_CUR)

            elif checkbytes == ZIP64_END_OF_CENTRAL_DIRECTORY:
                # check for ZIP64 end of central directory (section 4.3.14)
                check_condition(seen_central_directory,
                                "ZIP64 end of cental directory, but no central directory header")

                seen_zip64_end_of_central_dir = True

                # first read the size of the ZIP64 end of
                # central directory (section 4.3.14.1)
                checkbytes = self.infile.read(8)
                check_condition(len(checkbytes) == 8,
                                "not enough data for ZIP64 end of central directory header")

                len_zip64_end_of_central_directory = int.from_bytes(checkbytes, byteorder='little')
                check_condition(self.infile.tell() + len_zip64_end_of_central_directory <= self.fileresult.filesize,
                                "not enough data for ZIP64 end of central directory")

                # now skip over the rest of the data in the
                # ZIP64 end of central directory
                self.infile.seek(len_zip64_end_of_central_directory, os.SEEK_CUR)

            elif checkbytes == ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR:
                # check for ZIP64 end of central directory locator
                # (section 4.3.15)
                check_condition(seen_zip64_end_of_central_dir,
                                "ZIP64 end of cental directory locator, but no ZIP64 end of central directory")

                check_condition(self.infile.tell() + 16 <= self.fileresult.filesize,
                                "not enough data for ZIP64 end of central directory locator")

                # skip the locator data
                self.infile.seek(16, os.SEEK_CUR)
            elif checkbytes == END_OF_CENTRAL_DIRECTORY:
                # check for end of central directory (section 4.3.16)
                check_condition(seen_central_directory,
                                "end of cental directory, but no central directory header")

                check_condition(self.infile.tell() + 18 <= self.fileresult.filesize,
                                "not enough data for end of central directory header")

                # skip 16 bytes of the header
                self.infile.seek(16, os.SEEK_CUR)

                # read the ZIP comment length
                checkbytes = self.infile.read(2)
                len_zip_comment = int.from_bytes(checkbytes, byteorder='little')

                if len_zip_comment != 0:
                    # read the file comment
                    checkbytes = self.infile.read(len_zip_comment)
                    check_condition(len(checkbytes) == len_zip_comment,
                                    "not enough data for extra field in central directory")

                # end of ZIP file reached, so break out of the loop
                break




    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['zip', 'compressed']
        if self.android_signing:
            labels.append('apk')
            labels.append('android')

        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
