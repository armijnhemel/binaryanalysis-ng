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
(latest version: version 6.3.10)

Python's zipfile module starts looking at the end of the file
for a central directory. If multiple ZIP files have been concatenated
and the last ZIP file is at the end, then only this ZIP file
will be unpacked by Python's zipfile module. This is why this parser
first verifies a file to see where the ZIP data starts and where it ends
and carves the data if necessary. It does this by parsing from the start
of the file, instead of jumping to the end of the file and only rely on
the central directory.

A description of some of the underlying problems encountered
when writing this code can be found here:

http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html

as well as in the file 'doc/fileformats/zip.md' in this repository.

Also supported is a ZIP variant from Dahua. Dahua is a Chinese vendor that
is using the ZIP format for its firmware updates, but has changed the first
two characters of the file from PK to DH.
'''

import bz2
import os
import pathlib
import tempfile
import zipfile
import zlib

import pyaxmlparser

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import zip as kaitai_zip

MIN_VERSION = 0
MAX_VERSION = 63

# all known ZIP headers
ARCHIVE_EXTRA_DATA = b'PK\x06\x08'
CENTRAL_DIRECTORY = b'PK\x01\x02'
INSTAR_CENTRAL_DIRECTORY = b'PK\x01\x08'
DATA_DESCRIPTOR = b'PK\x07\x08'
DIGITAL_SIGNATURE = b'PK\x05\x05'
END_OF_CENTRAL_DIRECTORY = b'PK\x05\x06'
INSTAR_END_OF_CENTRAL_DIRECTORY = b'PK\x05\x09'
LOCAL_FILE_HEADER = b'PK\x03\x04'
ZIP64_END_OF_CENTRAL_DIRECTORY = b'PK\x06\x06'
ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR = b'PK\x06\x07'
DAHUA_LOCAL_FILE_HEADER = b'DH\x03\x04'
INSTAR_LOCAL_FILE_HEADER = b'PK\x03\x07'

ALL_HEADERS = [ARCHIVE_EXTRA_DATA, CENTRAL_DIRECTORY, DATA_DESCRIPTOR,
               DIGITAL_SIGNATURE, END_OF_CENTRAL_DIRECTORY,
               LOCAL_FILE_HEADER, ZIP64_END_OF_CENTRAL_DIRECTORY,
               ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR,
               DAHUA_LOCAL_FILE_HEADER, INSTAR_LOCAL_FILE_HEADER,
               INSTAR_CENTRAL_DIRECTORY, INSTAR_END_OF_CENTRAL_DIRECTORY]


class ZipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PK\x03\04'),
        #(0, b'PK\x03\07'),
        # http://web.archive.org/web/20190709133846/https://ipcamtalk.com/threads/dahua-ipc-easy-unbricking-recovery-over-tftp.17189/page-2
        (0, b'DH\x03\04')
    ]
    pretty_name = 'zip'

    # set the priority high so this one will be tried first, before
    # the parser for individual ZIP entries (see bottom of this file)
    priority = 1000

    def parse(self):
        self.encrypted = False
        self.zip64 = False

        self.dahua = False
        self.instar = False

        # store if there is an Android signing block:
        # https://source.android.com/security/apksigning/
        self.android_signing = False

        # For every local file header in the ZIP file there should
        # be a corresponding entry in the central directory.
        # Store the file names plus the CRC32 from the local file
        # headers as well as the central directory to see if these
        # correspond. Note: this won't necessarily work if data
        # descriptors are used (section 4.4.4) as then the CRC32
        # field might be set to 0 in the local file header but not
        # the central directory.
        local_files = []
        central_directory_files = []

        # store the order in which headers appear. This is to be
        # able to check the order in which all the different headers
        # appear in the file as the specification mandates a certain
        # ordering: local file headers cannot appear after the first
        # central directory entry and a digital signature will only
        # appear after the last entry in the central directory.
        order_for_headers = []

        # first do a simple sanity check for the most common case
        # where the file is a single ZIP archive that can be parsed
        # with the Kaitai Struct grammar. This means that sizes in
        # the local file headers are known and correct, and so on.
        # This is the most basic ZIP file format without any of the
        # countless exceptions that exist.
        try:
            self.data = kaitai_zip.Zip.from_io(self.infile)

            # store file names and CRC32 to see if they match in the local
            # file headers and in the end of central directory
            # TODO: extra sanity checks to see if the order in which
            # the different records/sections appear, see section 4.3.6.
            for file_header in self.data.sections:
                order_for_headers.append(file_header.section_type)
                if file_header.section_type == kaitai_zip.Zip.SectionTypes.dahua_local_file:
                    self.dahua = True
                if file_header.section_type == kaitai_zip.Zip.SectionTypes.instar_local_file:
                    self.instar = True
                if file_header.section_type in [kaitai_zip.Zip.SectionTypes.local_file, kaitai_zip.Zip.SectionTypes.dahua_local_file]:
                    local_files.append((file_header.body.header.file_name, file_header.body.header.crc32))
                    if file_header.body.header.flags.file_encrypted:
                        self.encrypted = True
                elif file_header.section_type == kaitai_zip.Zip.SectionTypes.central_dir_entry:
                    central_directory_files.append((file_header.body.file_name, file_header.body.crc32))
                elif file_header.section_type == kaitai_zip.Zip.SectionTypes.end_of_central_dir:
                    self.zip_comment = file_header.body.comment

            # some more sanity checks here: verify if the local files
            # and the central directory (including CRC32 values) match
            if len(local_files) != len(central_directory_files):
                raise UnpackParserException("local files and central directory files do not match")
            if set(local_files) != set(central_directory_files):
                raise UnpackParserException("local files and central directory files do not match")
            kaitai_success = True
        except (UnpackParserException, ValidationFailedError, UnicodeDecodeError, EOFError) as e:
            kaitai_success = False

        # in case the file cannot be successfully unpacked with
        # Kaitai Struct there is only the hard way left: parse from
        # the start of the file and keep track of everything manually.
        if not kaitai_success:
            # store if the previous header is a local file header.
            # Local file headers can only be interleaved by data
            # descriptors. All other headers should set this variable
            #  to False.
            previous_header_local = True

            # reset the order_for_headers list to get rid of any
            # possible old data.
            order_for_headers = []

            seen_end_of_central_directory = False
            seen_zip64_end_of_central_dir = False
            possible_android = False

            # store any unscanned data, such as APK signing blocks.
            # This data will later be written to a separate file.
            self.start_of_signing_block = 0
            self.end_of_signing_block = 0

            # go back to the start of the file
            self.infile.seek(0)

            seen_first_header = False

            while True:
                start_of_entry = self.infile.tell()
                buf = self.infile.read(4)
                check_condition(len(buf) == 4,
                                "not enough data for ZIP entry header")

                if buf not in [LOCAL_FILE_HEADER, DAHUA_LOCAL_FILE_HEADER]:
                    # process everything that is not a local file header, but
                    # either a ZIP section header or an Android signing signature.
                    if buf in ALL_HEADERS:
                        # parse a single ZIP header with Kaitai Struct
                        # first seek back to the start of the (possible) header
                        self.infile.seek(-4, os.SEEK_CUR)

                        # parse the ZIP section header using Kaitai Struct
                        try:
                            file_header = kaitai_zip.Zip.PkSection.from_io(self.infile)
                        except (UnpackParserException, ValidationFailedError, UnicodeDecodeError, EOFError) as e:
                            raise UnpackParserException(e.args)

                        order_for_headers.append(file_header.section_type)

                        if file_header.section_type == kaitai_zip.Zip.SectionTypes.central_dir_entry:
                            # store the file name (as byte string)
                            central_directory_files.append(file_header.body.file_name)
                            previous_header_local = False
                        elif file_header.section_type == kaitai_zip.Zip.SectionTypes.zip64_end_of_central_dir:
                            # first read the size of the ZIP64 end of
                            # central directory (section 4.3.14.1)
                            seen_zip64_end_of_central_dir = True
                            previous_header_local = False
                        elif file_header.section_type == kaitai_zip.Zip.SectionTypes.zip64_end_of_central_dir_locator:
                            # check for ZIP64 end of central directory locator
                            # (section 4.3.15)
                            previous_header_local = False
                        elif file_header.section_type == kaitai_zip.Zip.SectionTypes.end_of_central_dir:
                            # check for end of central directory (section 4.3.16)
                            previous_header_local = False

                            # read the ZIP comment length
                            self.zip_comment = file_header.body.comment

                            seen_end_of_central_directory = True

                            # end of ZIP file reached, so break out of the loop
                            break
                        elif file_header.section_type == kaitai_zip.Zip.SectionTypes.data_descriptor:
                            # challenge: this could be both a 32 bit and 64 bit
                            # data descriptor and it is not always easy to find
                            # which one is used possibly only until after it has
                            # been read.
                            # A hint is the ZIP version: if it is 4.5 or higher
                            # then it is very likely that it is the ZIP64 variant
                            if zip_version >= 45:
                                self.infile.seek(start_of_entry)
                                try:
                                    file_header = kaitai_zip.Zip.PkSection64.from_io(self.infile)
                                except (UnpackParserException, ValidationFailedError, UnicodeDecodeError, EOFError) as e:
                                    raise UnpackParserException(e.args)
                    else:
                        # There could be extra data in between the last local
                        # file header and the start of the central directory,
                        # despite the ZIP specification not allowing for this.
                        # A typical valid use is the Android signing block (v2 or v3).
                        # An invalid use would be malware that's hiding.
                        if self.android_signing or buf == b'\x00\x00\x00\x00' or possible_android or not has_data_descriptor:
                            # The Android signing block is explained at:
                            #
                            # https://source.android.com/security/apksigning/
                            #
                            # The code below is triggered under the following conditions:
                            #
                            # 1. data descriptors are used and it was already determined
                            #    that there is an Android signing block.
                            # 2. the bytes read are 0x00 0x00 0x00 0x00 which could
                            #    possibly be an APK signing v3 block, as it is possibly
                            #    padded.
                            # 3. there is a strong indication that it is an Android package
                            #    because an extra field specifically used in Android was used.
                            # 4. no data descriptors are used, meaning it might be a
                            #    length of a signing block.

                            # first go back to the beginning of the block
                            self.infile.seek(-4, os.SEEK_CUR)
                            self.start_of_signing_block = self.infile.tell()

                            # then read 8 bytes for the APK signing block size
                            buf = self.infile.read(8)
                            check_condition(len(buf) == 8,
                                            "not enough data for ZIP64 end of Android signing block")

                            android_signing_size = int.from_bytes(buf, byteorder='little')

                            # APK signing V3 might pad to 4096 bytes first,
                            # introduced in:
                            #
                            # https://android.googlesource.com/platform/tools/apksig/+/edf96cb79f533eb4255ee1b6aa2ba8bf9c1729b2
                            if android_signing_size == 0:
                                # read padding bytes
                                padding = 4096 - self.infile.tell() % 4096
                                padding_bytes = self.infile.read(padding)
                                check_condition(padding_bytes == padding * b'\x00',
                                                "invalid padding bytes for APK v3 signing block")

                                # then read 8 bytes for the APK signing block size
                                buf = self.infile.read(8)
                                check_condition(len(buf) == 8, "not enough data for Android signing block")
                                android_signing_size = int.from_bytes(buf, byteorder='little')
                            elif self.infile.tell() + android_signing_size > self.infile.size:
                                # there could be fewer than 8 padding bytes, leading to weird results.
                                # first go back to the beginning of the block
                                self.infile.seek(-8, os.SEEK_CUR)

                                # then pad
                                padding = 4096 - self.infile.tell() % 4096
                                padding_bytes = self.infile.read(padding)
                                check_condition(padding_bytes == padding * b'\x00',
                                                "invalid padding bytes for APK v3 signing block")

                                # then read 8 bytes for the APK signing block size
                                buf = self.infile.read(8)
                                check_condition(len(buf) == 8,
                                                "not enough data for ZIP64 end of Android signing block")

                                android_signing_size = int.from_bytes(buf, byteorder='little')

                            # as the last 16 bytes are for the Android signing block
                            # the block has to be at least 16 bytes.
                            check_condition(android_signing_size >= 16,
                                            "wrong size for Android signing block")

                            # the signing block cannot be (partially)
                            # outside of the file
                            check_condition(self.infile.tell() + android_signing_size <= self.infile.size,
                                            "not enough data for Android signing block")

                            # then skip the signing block, except the
                            # last 16 bytes to have an extra sanity check
                            self.infile.seek(android_signing_size - 16, os.SEEK_CUR)
                            buf = self.infile.read(16)
                            check_condition(buf == b'APK Sig Block 42',
                                            "wrong magic for Android signing block")
                            self.android_signing = True
                            self.end_of_signing_block = self.infile.tell()
                        else:
                            # This is not a signing block, but something else.
                            break
                    continue

                # continue with the local file headers
                if buf == LOCAL_FILE_HEADER and not previous_header_local:
                    # this should not happen in a valid ZIP file:
                    # local file headers should not be interleaved
                    # with other headers, except data descriptors.
                    break

                # parse a single local file header with Kaitai Struct
                self.infile.seek(-4, os.SEEK_CUR)
                try:
                    file_header = kaitai_zip.Zip.PkSection.from_io(self.infile)
                except (UnpackParserException, ValidationFailedError, UnicodeDecodeError, EOFError) as e:
                    raise UnpackParserException(e.args)

                order_for_headers.append(file_header.section_type)
                compressed_size = file_header.body.header.len_body_compressed
                uncompressed_size = file_header.body.header.len_body_uncompressed

                zip_version = file_header.body.header.version.version

                check_condition(MIN_VERSION <= zip_version <= MAX_VERSION,
                                f"invalid ZIP version {zip_version}")

                if file_header.body.header.flags.file_encrypted:
                    self.encrypted = True

                has_data_descriptor = False

                # see if there is a data descriptor for regular files in the
                # general purpose bit flag. This usually won't be set for
                # directories although sometimes it is
                # (example: framework/ext.jar from various Android versions)
                if file_header.body.header.flags.has_data_descriptor:
                    has_data_descriptor = True

                # record if an entry is a zip64 entry
                is_zip64_entry = False

                # the extra fields are important, especially to check for
                # any ZIP64 extension, as it contains updated values for
                # the compressed size and uncompressed size (section 4.5)
                if type(file_header.body.header.extra) != kaitai_zip.Zip.Empty:
                    for extra in file_header.body.header.extra.entries:
                        # skip any unknown extra fields for now
                        if extra.code == kaitai_zip.Zip.ExtraCodes.zip_align:
                            # the zip_align extra field is only used in Android APK packages
                            possible_android = True
                        elif extra.code == kaitai_zip.Zip.ExtraCodes.zip64:
                            # ZIP64, section 4.5.3
                            # according to 4.4.3.2 PKZIP 4.5 or later is
                            # needed to unpack ZIP64 files.
                            check_condition(zip_version >= 45, "wrong minimal needed version for ZIP64")

                            # according to the official ZIP specifications the length of the
                            # header should be 28, but there are files where this field is
                            # 16 bytes long instead, sigh...
                            check_condition(len(extra.body) in [16, 28],
                                            "wrong extra field header length for ZIP64")

                            zip64_uncompressed_size = int.from_bytes(extra.body[:8], byteorder='little')
                            zip64_compressed_size = int.from_bytes(extra.body[8:16], byteorder='little')

                            is_zip64_entry = True
                            orig_compressed_size = compressed_size

                            # replace compressed size and uncompressed size but only
                            # if they have the special value 0xffffffff
                            if compressed_size == 0xffffffff:
                                compressed_size = zip64_compressed_size
                            if uncompressed_size == 0xffffffff:
                                uncompressed_size = zip64_uncompressed_size

                if is_zip64_entry:
                    # skip the data but only if it was changed as there is
                    # a slight chance there is a file where the size was not
                    # changed. In that case the body is correctly read by
                    # the kaitai struct code.
                    if orig_compressed_size == 0xffffffff:
                        self.infile.seek(compressed_size, os.SEEK_CUR)

                # Section 4.4.4, bit 3:
                # "If this bit is set, the fields crc-32, compressed
                # size and uncompressed size are set to zero in the
                # local header.  The correct values are put in the
                # data descriptor immediately following the compressed
                # data."
                #
                # This is not necessarily correct though: there are files
                # where a data descriptor has been set and the sizes
                # and CRC in the local file header have not been changed.
                dd_found = False

                if (not file_header.body.header.file_name.endswith('/') and compressed_size == 0) or has_data_descriptor and compressed_size == 0:
                    # first store where the possible data descriptor starts
                    start_of_possible_data_descriptor = self.infile.tell()

                    # In case the length is not known it is very difficult
                    # to see where the data ends so it is needed to search for
                    # a specific signature. This can either be:
                    #
                    # * data descriptor header
                    # * local file header
                    # * central directory header
                    #
                    # Whichever appears first in the data will be processed.
                    while True:
                        # store the current position of the pointer in the file
                        current_position = self.infile.tell()
                        tmppos = -1

                        # read a number of bytes to be searched for markers
                        buf = self.infile.read(50000)
                        new_cur_pos = self.infile.tell()

                        # EOF is reached
                        if buf == b'':
                            break

                        best_so_far = tmppos

                        # first search for the common marker for data descriptors,
                        # but only if the right flag has been set in the general
                        # purpose bit flag.
                        if has_data_descriptor:
                            ddpos = -1
                            while True:
                                ddpos = buf.find(DATA_DESCRIPTOR, ddpos+1)
                                if ddpos != -1:
                                    dd_found = True

                                    # sanity check to make sure that the
                                    # compressed size makes sense in the data descriptor
                                    # makes sense.
                                    self.infile.seek(current_position + ddpos + 8)
                                    tmp_compressed_size = int.from_bytes(self.infile.read(4), byteorder='little')

                                    if current_position + ddpos - start_of_possible_data_descriptor == tmp_compressed_size:
                                        tmppos = ddpos
                                        break
                                else:
                                    break

                            if ddpos != -1:
                                best_so_far = ddpos

                        # search for a local file header which indicates
                        # the next entry in the ZIP file (not a Dahua local file
                        # header as that is always the first one in the file)
                        local_header_pos = buf.find(LOCAL_FILE_HEADER)
                        if local_header_pos != -1 and (local_header_pos < tmppos or tmppos == -1):
                            # In case the file that is stored is an empty
                            # file, then there will be no data descriptor field
                            # so just continue as normal.
                            if current_position + local_header_pos == start_of_possible_data_descriptor:
                                self.infile.seek(current_position)
                                break

                            # if there is a data descriptor, then the 12
                            # bytes preceding the next header are:
                            # * crc32
                            # * compressed size
                            # * uncompressed size
                            # section 4.3.9
                            if has_data_descriptor:
                                if current_position + local_header_pos - start_of_possible_data_descriptor > 12:
                                    self.infile.seek(current_position + local_header_pos - 8)
                                    tmp_compressed_size = int.from_bytes(self.infile.read(4), byteorder='little')

                                    # and return to the original position
                                    self.infile.seek(new_cur_pos)
                                    if current_position + local_header_pos - start_of_possible_data_descriptor == tmp_compressed_size + 16:
                                        if tmppos == -1:
                                            tmppos = local_header_pos
                                        else:
                                            tmppos = min(local_header_pos, tmppos)
                            else:
                                if tmppos == -1:
                                    tmppos = local_header_pos
                                else:
                                    tmppos = min(local_header_pos, tmppos)
                            self.infile.seek(new_cur_pos)

                        # then search for the start of the central directory
                        centraldirpos = buf.find(CENTRAL_DIRECTORY)
                        if centraldirpos != -1:
                            # In case the file that is stored is an empty
                            # file, then there will be no data descriptor field
                            # so just continue as normal.
                            if current_position + centraldirpos == start_of_possible_data_descriptor:
                                self.infile.seek(current_position)
                                break

                            # if there is a data descriptor, then the 12
                            # bytes preceding the next header are:
                            # * crc32
                            # * compressed size
                            # * uncompressed size
                            # section 4.3.9
                            if has_data_descriptor:
                                if current_position + centraldirpos - start_of_possible_data_descriptor > 12:
                                    self.infile.seek(current_position + centraldirpos - 8)
                                    tmp_compressed_size = int.from_bytes(self.infile.read(4), byteorder='little')
                                    # and return to the original position
                                    self.infile.seek(new_cur_pos)
                                    if current_position + centraldirpos - start_of_possible_data_descriptor == tmp_compressed_size + 16:
                                        if tmppos == -1:
                                            tmppos = centraldirpos
                                        else:
                                            tmppos = min(centraldirpos, tmppos)
                                    else:
                                        if current_position + centraldirpos - start_of_possible_data_descriptor > 16:
                                            self.infile.seek(current_position + centraldirpos - 16)
                                            tmpbytes = self.infile.read(16)
                                            if tmpbytes == b'APK Sig Block 42':
                                                self.android_signing = True
                                            # and (again) return to the
                                            # original position
                                            self.infile.seek(new_cur_pos)
                            else:
                                if tmppos == -1:
                                    tmppos = centraldirpos
                                else:
                                    tmppos = min(centraldirpos, tmppos)

                            self.infile.seek(new_cur_pos)

                            oldtmppos = tmppos

                            # extra sanity check: see if the
                            # file names are the same
                            origpos = self.infile.tell()
                            self.infile.seek(current_position + tmppos + 42)
                            checkfn = self.infile.read(file_header.body.header.len_file_name)
                            if file_header.body.header.file_name != checkfn:
                                tmppos = oldtmppos
                            self.infile.seek(origpos)
                        if tmppos != -1:
                            self.infile.seek(current_position + tmppos)
                            break

                        # have a small overlap the size of a possible header
                        # unless it is the last 4 bytes of the file to avoid
                        # getting stuck in a loop.
                        if self.infile.tell() == self.infile.size:
                            break
                        self.infile.seek(-4, os.SEEK_CUR)
                else:
                    # default
                    pass

            # there always has to be an end of central directory
            check_condition(seen_end_of_central_directory, "no end of central directory found")

        self.unpacked_size = self.infile.tell()

        # If the ZIP file is at the end of the file then the ZIP module
        # from Python will do a lot of the heavy lifting. If not it first
        # needs to be carved.
        #
        # Malformed ZIP files that need a workaround exist:
        # http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442
        if self.unpacked_size == self.infile.size and not self.dahua:
            self.carved = False
        else:
            # else carve the file from the larger ZIP first
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(self.temporary_file[0]).close()
            self.carved = True
            if self.dahua:
                # reopen the file in write mode
                dahua = open(self.temporary_file[1], 'r+b')
                dahua.seek(0)
                dahua.write(b'PK')
                dahua.close()

        if not self.carved:
            # seek to the right offset, even though that's
            # probably not necessary.
            self.infile.seek(0)

        # store if an unsupported compression was found
        self.unsupported_compression = False

        # Some ZIP files store directory names without a slash. Although
        # this is most probably allowed according to the specifications
        # many tools cannot correctly unpack these files and instead of
        # looking at other characteristics of the file will unpack the
        # directory as a regular file:
        #
        # http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442
        self.dirs_without_slash = []

        try:
            if not self.carved:
                unpackzipfile = zipfile.ZipFile(self.infile)
            else:
                unpackzipfile = zipfile.ZipFile(self.temporary_file[1])
            if not self.encrypted:

                # check to see if Python's zipfile module thinks it's a valid file
                if unpackzipfile.testzip() is not None:
                    if self.carved:
                        # cleanup
                        os.unlink(self.temporary_file[1])
                    raise UnpackParserException("bad zip file according to testzip()")

            self.zipfiles = unpackzipfile.namelist()
            self.zipinfolist = unpackzipfile.infolist()

            for z in self.zipinfolist:
                # only stored, deflate, bzip2 and lzma are supported
                # in Python's standard zipfile module.
                if z.compress_type not in [0, 8, 12, 14]:
                    self.unsupported_compression = True
                    break
                if z.file_size == 0 and not z.is_dir() and z.external_attr & 0x10 == 0x10:
                    self.dirs_without_slash.append(z)
                file_path = pathlib.Path(z.filename)

                # Although absolute paths are not permitted according
                # to the ZIP specification these files exist or can easily
                # be created.
                if file_path.is_absolute():
                    try:
                        file_path = file_path.relative_to('/')
                    except ValueError:
                        file_path = file_path.relative_to('//')

        except (OSError, zipfile.BadZipFile, NotImplementedError, ValueError) as e:
            if self.carved:
                # cleanup
                os.unlink(self.temporary_file[1])
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        # no files need to be unpacked for encrypted files
        # only stored, deflate, bzip2 and lzma are currently
        # supported in Python's zipfile module.
        if self.encrypted or self.unsupported_compression:
            if self.carved:
                # cleanup
                os.unlink(self.temporary_file[1])
            return

        # unpack archve comment. Archive comments (and file comments) can
        # contain binary data as the ZIP specification doesn't put any
        # restrictions on it.
        if self.zip_comment != b'':
            file_path = pathlib.Path(pathlib.Path(self.infile.name).name)
            suffix = file_path.suffix + '.comment'
            file_path = file_path.with_suffix(suffix)
            with meta_directory.unpack_regular_file(file_path, is_extradata=True) as (unpacked_md, outfile):
                outfile.write(self.zip_comment)
                yield unpacked_md

        if self.android_signing:
            signing_block_length = self.end_of_signing_block - self.start_of_signing_block

            if signing_block_length != 0:
                file_path = pathlib.Path(pathlib.Path(self.infile.name).name)
                suffix = file_path.suffix + '.signing_block'
                file_path = file_path.with_suffix(suffix)
                with meta_directory.unpack_regular_file(file_path, is_extradata=True) as (unpacked_md, outfile):
                    self.infile.seek(self.start_of_signing_block)
                    outfile.write(self.infile.read(signing_block_length))
                    yield unpacked_md

        if not self.carved:
            unpackzipfile = zipfile.ZipFile(self.infile)
        else:
            unpackzipfile = zipfile.ZipFile(self.temporary_file[1])

        # Extract files or create a directory for files that zipfile
        # thinks are files, but are actually directories.
        # There are some files where there are relative entries.
        # Care should be taken to make sure that the correct
        # names are used.
        #
        # Examples:
        # https://github.com/iBotPeaches/Apktool/issues/1498
        # https://github.com/iBotPeaches/Apktool/issues/1589
        #
        # Test data can be found in the Apktool repository
        for z in self.zipinfolist:
            file_path = pathlib.Path(z.filename)
            file_path_parts = file_path.parts

            # mimic behaviour of unzip and p7zip
            # that remove '..' from paths.
            clean_file_path_parts = []
            for part in file_path_parts:
                if part == '..':
                    continue
                clean_file_path_parts.append(part)

            check_condition(clean_file_path_parts != [],
                            'invalid file name in ZIP file')

            file_path = pathlib.Path(*clean_file_path_parts)

            # Absolute paths are not permitted according to the ZIP
            # specification so rework to relative paths. This
            # means that the files will be unpacked in the "rel"
            # directory instead of the "abs" directory. This is
            # intended behaviour and consistent with how other tools
            # unpack data.
            if file_path.is_absolute():
                try:
                    file_path = file_path.relative_to('/')
                except ValueError:
                    file_path = file_path.relative_to('//')

            if z in self.dirs_without_slash:
                # create the directory
                meta_directory.unpack_directory(file_path)
            else:
                try:
                    if not z.is_dir():
                        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                            outfile.write(unpackzipfile.read(z))
                            yield unpacked_md

                        # unpack file comments.
                        if z.comment != b'':
                            suffix = file_path.suffix + '.file_comment'
                            file_path = file_path.with_suffix(suffix)
                            with meta_directory.unpack_regular_file(file_path, is_extradata=True) as (unpacked_md, outfile):
                                outfile.write(z.comment)
                                yield unpacked_md
                    else:
                        meta_directory.unpack_directory(file_path)
                except NotADirectoryError:
                    # TODO: find out what to do here. This happens
                    # sometimes with zip files with symbolic links from
                    # one directory to another.
                    pass

        if self.carved:
            # cleanup
            os.unlink(self.temporary_file[1])

    @property
    def labels(self):
        labels = ['zip', 'compressed']
        if self.encrypted:
            labels.append('encrypted')
        if self.android_signing:
            labels.append('apk')
            labels.append('android')
        if self.dahua:
            labels.append('dahua')
        if self.instar:
            labels.append('instar zip')

        return labels

    @property
    def metadata(self):
        labels = []
        zip_name = pathlib.Path(self.infile.name)

        is_opc = False
        for z in self.zipinfolist:
            # https://www.python.org/dev/peps/pep-0427/
            if 'dist-info/WHEEL' in z.filename:
                labels.append('python wheel')
            # https://setuptools.readthedocs.io/en/latest/formats.html
            if z.filename == 'EGG-INFO/PKG-INFO':
                labels.append('python egg')
            if z.filename in ['AndroidManifest.xml', 'classes.dex']:
                if zip_name.suffix.lower() == '.apk':
                    labels.append('android')
                    labels.append('apk')

            # https://source.android.com/devices/tech/ota/apex
            if z.filename == 'apex_pubkey' and zip_name.suffix.lower() == '.apex':
                labels.append('android')
                labels.append('apex')

            # https://source.android.com/devices/tech/ota/apex
            if z.filename == 'original_apex' and zip_name.suffix.lower() == '.capex':
                labels.append('android')
                labels.append('compressed apex')

            # https://dotlottie.io/structure/#dotlottie-structure
            if z.filename == 'manifest.json':
                if zip_name.suffix.lower() == '.lottie':
                    labels.append('lottie')

            # https://en.wikipedia.org/wiki/Open_Packaging_Conventions
            if z.filename == '[Content_Types].xml':
                labels.append("Open Packaging Conventions")
                is_opc = True

        if is_opc:
            for z in self.zipinfolist:
                if zip_name.suffix.lower() == '.nupkg':
                    if z.filename.endswith('.nuspec'):
                        labels.append('nuget')
                        break

        if not self.carved:
            zfile = self.infile
        else:
            zfile = self.temporary_file[1]

        if 'android' in self.labels:
            try:
                # TODO: process apk results
                apk = pyaxmlparser.APK(zfile)
            except:
                pass

        metadata = {}
        metadata['zip type'] = labels
        return metadata


class ZipEntryUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PK\x03\04'),
        #(0, b'PK\x03\07'),
        # http://web.archive.org/web/20190709133846/https://ipcamtalk.com/threads/dahua-ipc-easy-unbricking-recovery-over-tftp.17189/page-2
        (0, b'DH\x03\04')
    ]
    pretty_name = 'zip_entry'

    def parse(self):
        self.encrypted = False
        self.zip64 = False

        self.dahua = False
        self.instar = False

        try:
            self.file_header = kaitai_zip.Zip.PkSection.from_io(self.infile)
        except (UnpackParserException, ValidationFailedError, UnicodeDecodeError, EOFError) as e:
            raise UnpackParserException(e.args)

        if self.file_header.section_type == kaitai_zip.Zip.SectionTypes.dahua_local_file:
            self.dahua = True
        elif self.file_header.section_type == kaitai_zip.Zip.SectionTypes.instar_local_file:
            self.instar = True

        if self.file_header.body.header.flags.file_encrypted:
            self.encrypted = True

        # only support regular ZIP entries for now, not ZIP64
        compressed_size = self.file_header.body.header.len_body_compressed
        uncompressed_size = self.file_header.body.header.len_body_uncompressed
        check_condition(compressed_size != 0xffffffff, 'ZIP64 not supported')
        check_condition(uncompressed_size != 0xffffffff, 'ZIP64 not supported')

        # then check if the file is a regular file or a directory (TODO)
        check_condition(compressed_size > 0, 'only regular files supported for now')
        check_condition(uncompressed_size > 0, 'only regular files supported for now')

        if not self.encrypted:
            if self.file_header.body.header.compression_method == kaitai_zip.Zip.Compression.deflated:
                try:
                    self.decompressed_data = zlib.decompress(self.file_header.body.body, -15)
                except Exception as e:
                    raise UnpackParserException(e.args)
            elif self.file_header.body.header.compression_method == kaitai_zip.Zip.Compression.bzip2:
                try:
                    self.decompressed_data = bz2.decompress(self.file_header.body.body)
                except Exception as e:
                    raise UnpackParserException(e.args)
            elif self.file_header.body.header.compression_method == kaitai_zip.Zip.Compression.lzma:
                try:
                    decompressor = zipfile.LZMADecompressor()
                    self.decompressed_data = decompressor.decompress(self.file_header.body.body)
                except Exception as e:
                    raise UnpackParserException(e.args)
            elif self.file_header.body.header.compression_method == kaitai_zip.Zip.Compression.none:
                self.decompressed_data = self.file_header.body.body
            else:
                raise UnpackParserException("unsupported compression")

            check_condition(len(self.decompressed_data) == uncompressed_size,
                            "wrong declared uncompresed size or incomplete decompression")

        file_path = pathlib.Path(self.file_header.body.header.file_name)
        file_path_parts = file_path.parts

        # mimic behaviour of unzip and p7zip
        # that remove '..' from paths.
        clean_file_path_parts = []
        for part in file_path_parts:
            if part == '..':
                continue
            clean_file_path_parts.append(part)

        check_condition(clean_file_path_parts != [],
                        'invalid file name in ZIP file')

        self.file_path = pathlib.Path(*clean_file_path_parts)

        # Absolute paths are not permitted according to the ZIP
        # specification so rework to relative paths. This
        # means that the files will be unpacked in the "rel"
        # directory instead of the "abs" directory. This is
        # intended behaviour and consistent with how other tools
        # unpack data.
        if self.file_path.is_absolute():
            try:
                self.file_path = self.file_path.relative_to('/')
            except ValueError:
                self.file_path = self.file_path.relative_to('//')

    def unpack(self, meta_directory):
        if not self.encrypted:
            with meta_directory.unpack_regular_file(self.file_path) as (unpacked_md, outfile):
                outfile.write(self.decompressed_data)
                yield unpacked_md

    @property
    def labels(self):
        labels = ['zip_entry', 'compressed']
        if self.encrypted:
            labels.append('encrypted')
        if self.dahua:
            labels.append('dahua')
        if self.instar:
            labels.append('instar zip')

        return labels

    metadata = {}
