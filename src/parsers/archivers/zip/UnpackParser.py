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
(latest version: version 6.3.9)

This parser first verifies a file to see where the ZIP data
starts and where it ends.

Python's zipfile module starts looking at the end of the file
for a central directory. If multiple ZIP files have been concatenated
and the last ZIP file is at the end, then only this ZIP file
will be unpacked by Python's zipfile module.

A description of some of the underlying problems encountered
when writing this code can be found here:

http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html

Also supported is a ZIP variant from Dahua. Dahua is a Chinese vendor that
is using the ZIP format for its firmware updates, but has changed the first
two characters of the file from PK to DH.
'''

import os
import pathlib
import tempfile
import zipfile

import pyaxmlparser

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import zip as kaitai_zip

MIN_VERSION = 0
MAX_VERSION = 90

# all known ZIP headers
ARCHIVE_EXTRA_DATA = b'PK\x06\x08'
CENTRAL_DIRECTORY = b'PK\x01\x02'
DATA_DESCRIPTOR = b'PK\x07\x08'
DIGITAL_SIGNATURE = b'PK\x05\x05'
END_OF_CENTRAL_DIRECTORY = b'PK\x05\x06'
LOCAL_FILE_HEADER = b'PK\x03\x04'
ZIP64_END_OF_CENTRAL_DIRECTORY = b'PK\x06\x06'
ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR = b'PK\x06\x07'
DAHUA_LOCAL_FILE_HEADER = b'DH\x03\x04'

ALL_HEADERS = [ARCHIVE_EXTRA_DATA, CENTRAL_DIRECTORY, DATA_DESCRIPTOR,
               DIGITAL_SIGNATURE, END_OF_CENTRAL_DIRECTORY,
               LOCAL_FILE_HEADER, ZIP64_END_OF_CENTRAL_DIRECTORY,
               ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR,
               DAHUA_LOCAL_FILE_HEADER]


class ZipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PK\x03\04'),
        # http://web.archive.org/web/20190709133846/https://ipcamtalk.com/threads/dahua-ipc-easy-unbricking-recovery-over-tftp.17189/page-2
        (0, b'DH\x03\04')
    ]
    pretty_name = 'zip'

    def parse(self):
        self.encrypted = False
        self.zip64 = False

        self.dahua = False

        # store if there is an Android signing block:
        # https://source.android.com/security/apksigning/
        self.android_signing = False

        # In a ZIP file there are file entries, followed by a central
        # directory, possibly with other headers following/preceding
        # store the local file names to check if they appear in the
        # central directory in the same order (optional)
        local_files = []
        central_directory_files = []

        # first do a short sanity check for the most common case
        # where the file is a single ZIP archive that can be parsed
        # with the Kaitai Struct grammar. In that case many checks
        # can be skipped as these have already been implemented in
        # Kaitai Struct.
        try:
            self.data = kaitai_zip.Zip.from_io(self.infile)

            # store file names and CRC32 to see if they match in the local
            # file headers and in the end of central directory
            for s in self.data.sections:
                if s.section_type == kaitai_zip.Zip.SectionTypes.dahua_local_file:
                    self.dahua = True
                if s.section_type == kaitai_zip.Zip.SectionTypes.local_file or s.section_type == kaitai_zip.Zip.SectionTypes.dahua_local_file:
                    local_files.append((s.body.header.file_name, s.body.header.crc32))
                    if s.body.header.flags.file_encrypted:
                        self.encrypted = True
                elif s.section_type == kaitai_zip.Zip.SectionTypes.central_dir_entry:
                    central_directory_files.append((s.body.file_name, s.body.crc32))
                elif s.section_type == kaitai_zip.Zip.SectionTypes.end_of_central_dir:
                    self.zip_comment = s.body.comment

            # some more sanity checks here: verify if the local files
            # and the central directory (including CRC32 values) match
            if len(local_files) != len(central_directory_files):
                raise UnpackParserException("local files and central directory files do not match")
            if set(local_files) != set(central_directory_files):
                raise UnpackParserException("local files and central directory files do not match")
            self.kaitai_success = True
        except (UnpackParserException, ValidationFailedError, UnicodeDecodeError, EOFError) as e:
            self.kaitai_success = False

        # in case the file cannot be successfully unpacked
        # there is only the hard way left: parse from the start
        # and keep track of everything manually.
        if not self.kaitai_success:
            seen_end_of_central_directory = False
            in_local_entry = True
            seen_zip64_end_of_central_dir = False
            possible_android = False

            # go back to the start of the file
            self.infile.seek(0)

            seen_first_header = False

            while True:
                # first read the header
                start_of_entry = self.infile.tell()
                buf = self.infile.read(4)
                check_condition(len(buf) == 4,
                                "not enough data for ZIP entry header")
                if buf != LOCAL_FILE_HEADER and buf != DAHUA_LOCAL_FILE_HEADER:
                    # process everything that is not a local file header, but
                    # either a ZIP header or an Android signing signature.

                    # check the different file headers
                    if buf in ALL_HEADERS:
                        # parse a single local file header with Kaitai Struct
                        self.infile.seek(-4, os.SEEK_CUR)
                        try:
                            file_header = kaitai_zip.Zip.PkSection.from_io(self.infile)
                        except (UnpackParserException, ValidationFailedError, UnicodeDecodeError, EOFError) as e:
                            raise UnpackParserException(e.args)

                        if file_header.section_type == kaitai_zip.Zip.SectionTypes.central_dir_entry:
                            # store the file name (as byte string)
                            central_directory_files.append(file_header.body.file_name)
                            in_local_entry = False
                        elif buf == ZIP64_END_OF_CENTRAL_DIRECTORY:
                            # first read the size of the ZIP64 end of
                            # central directory (section 4.3.14.1)
                            seen_zip64_end_of_central_dir = True
                            in_local_entry = False
                        elif buf == ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR:
                            # check for ZIP64 end of central directory locator
                            # (section 4.3.15)
                            in_local_entry = False
                        elif buf == END_OF_CENTRAL_DIRECTORY:
                            # check for end of central directory (section 4.3.16)
                            in_local_entry = False

                            # read the ZIP comment length
                            self.zip_comment = file_header.body.comment

                            seen_end_of_central_directory = True

                            # end of ZIP file reached, so break out of the loop
                            break
                        elif buf == DATA_DESCRIPTOR:
                            pass
                    else:
                        # then check to see if this is possibly an Android
                        # signing block (v2 or v3):
                        #
                        # https://source.android.com/security/apksigning/
                        #
                        # The Android signing block is squeezed in between the
                        # latest entry and the central directory, despite the
                        # ZIP specification not allowing this. There have been
                        # various versions.
                        #
                        # The following code is triggered under three conditions:
                        #
                        # 1. data descriptors are used and it was already determined
                        #    that there is an Android signing block.
                        # 2. the bytes read are 0x00 0x00 0x00 0x00 which could
                        #    possibly be an APK signing v3 block, as it is possibly
                        #    padded.
                        # 3. no data descriptors are used, meaning it might be a
                        #    length of a signing block.
                        if self.android_signing or buf == b'\x00\x00\x00\x00' or possible_android or not has_data_descriptor:
                            # first go back to the beginning of the block
                            self.infile.seek(-4, os.SEEK_CUR)

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
                            elif self.infile.tell() + android_signing_size > self.fileresult.filesize:
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
                            check_condition(self.infile.tell() + android_signing_size <= self.fileresult.filesize,
                                            "not enough data for Android signing block")

                            # then skip the signing block, except the
                            # last 16 bytes to have an extra sanity check
                            self.infile.seek(android_signing_size - 16, os.SEEK_CUR)
                            buf = self.infile.read(16)
                            check_condition(buf == b'APK Sig Block 42',
                                            "wrong magic for Android signing block")
                            self.android_signing = True
                        else:
                            break
                    continue

                # continue with the local file headers instead
                if buf == LOCAL_FILE_HEADER and not in_local_entry:
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

                compressed_size = file_header.body.header.len_body_compressed
                uncompressed_size = file_header.body.header.len_body_uncompressed

                broken_zip_version = False

                # some files observed in the wild have a weird version
                if file_header.body.header.version in [0x30a, 0x314]:
                    broken_zip_version = True

                check_condition(file_header.body.header.version >= MIN_VERSION,
                                "invalid ZIP version %d" % file_header.body.header.version)

                if not broken_zip_version:
                    check_condition(file_header.body.header.version <= MAX_VERSION,
                                    "invalid ZIP version %d" % file_header.body.header.version)

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
                            possible_android = True
                        if extra.code == kaitai_zip.Zip.ExtraCodes.zip64:
                            # ZIP64, section 4.5.3
                            # according to 4.4.3.2 PKZIP 4.5 or later is
                            # needed to unpack ZIP64 files.
                            check_condition(file_header.body.header.version >= 45, "wrong minimal needed version for ZIP64")

                            # according to the official ZIP specifications the length of the
                            # header should be 28, but there are files where this field is
                            # 16 bytes long instead, sigh...
                            check_condition(len(extra.body) in [16, 28],
                                            "wrong extra field header length for ZIP64")

                            zip64uncompressedsize = int.from_bytes(extra.body[:8], byteorder='little')
                            zip64compressedsize = int.from_bytes(extra.body[8:16], byteorder='little')

                            is_zip64_entry = True
                            orig_compressed_size = compressed_size

                            # replace compressed size and uncompressed size but only
                            # if they have the special value 0xffffffff
                            if compressed_size == 0xffffffff:
                                compressed_size = zip64compressedsize
                            if uncompressed_size == 0xffffffff:
                                uncompressed_size = zip64uncompressedsize

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
                # and CRC have not been changed.
                ddfound = False
                ddsearched = False

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
                        newcurpos = self.infile.tell()

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
                                    ddsearched = True
                                    ddfound = True

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
                        localheaderpos = buf.find(LOCAL_FILE_HEADER)
                        if localheaderpos != -1 and (localheaderpos < tmppos or tmppos == -1):
                            # In case the file that is stored is an empty
                            # file, then there will be no data descriptor field
                            # so just continue as normal.
                            if current_position + localheaderpos == start_of_possible_data_descriptor:
                                self.infile.seek(current_position)
                                break

                            # if there is a data descriptor, then the 12
                            # bytes preceding the next header are:
                            # * crc32
                            # * compressed size
                            # * uncompressed size
                            # section 4.3.9
                            if has_data_descriptor:
                                if current_position + localheaderpos - start_of_possible_data_descriptor > 12:
                                    self.infile.seek(current_position + localheaderpos - 8)
                                    tmpcompressedsize = int.from_bytes(self.infile.read(4), byteorder='little')
                                    # and return to the original position
                                    self.infile.seek(newcurpos)
                                    if current_position + localheaderpos - start_of_possible_data_descriptor == tmpcompressedsize + 16:
                                        if tmppos == -1:
                                            tmppos = localheaderpos
                                        else:
                                            tmppos = min(localheaderpos, tmppos)
                            else:
                                if tmppos == -1:
                                    tmppos = localheaderpos
                                else:
                                    tmppos = min(localheaderpos, tmppos)
                            self.infile.seek(newcurpos)

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
                                    tmpcompressedsize = int.from_bytes(self.infile.read(4), byteorder='little')
                                    # and return to the original position
                                    self.infile.seek(newcurpos)
                                    if current_position + centraldirpos - start_of_possible_data_descriptor == tmpcompressedsize + 16:
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
                                            self.infile.seek(newcurpos)
                            else:
                                if tmppos == -1:
                                    tmppos = centraldirpos
                                else:
                                    tmppos = min(centraldirpos, tmppos)

                            self.infile.seek(newcurpos)

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
                        # unless it is the last 4 bytes of the file
                        if self.infile.tell() == self.fileresult.filesize:
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
        if self.unpacked_size == self.fileresult.filesize and not self.dahua:
            self.carved = False
        else:
            # else carve the file from the larger ZIP first
            self.temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
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

        # Malformed ZIP files where directories are stored as normal files exist:
        # http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442
        self.faulty_files = []

        zip_test_result = None

        try:
            if not self.carved:
                unpackzipfile = zipfile.ZipFile(self.infile)
            else:
                unpackzipfile = zipfile.ZipFile(self.temporary_file[1])
            if not self.encrypted:
                zip_test_result = unpackzipfile.testzip()

            if zip_test_result is not None:
                if self.carved:
                    # cleanup
                    os.unlink(self.temporary_file[1])
                raise UnpackParserException("bad zip file according to testzip()")

            self.zipfiles = unpackzipfile.namelist()
            self.zipinfolist = unpackzipfile.infolist()
            oldcwd = os.getcwd()
            for z in self.zipinfolist:
                # only stored, deflate, bzip2 and lzma are supported
                # in Python's zipfile module.
                if z.compress_type not in [0, 8, 12, 14]:
                    self.unsupported_compression = True
                    break
                if z.file_size == 0 and not z.is_dir() and z.external_attr & 0x10 == 0x10:
                    self.faulty_files.append(z)

        except (OSError, zipfile.BadZipFile, NotImplementedError) as e:
            if self.carved:
                # cleanup
                os.unlink(self.temporary_file[1])
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        # no files need to be unpacked for encrypted files
        if self.encrypted:
            if self.carved:
                # cleanup
                os.unlink(self.temporary_file[1])
            return unpacked_files

        # only stored, deflate, bzip2 and lzma are currently
        # supported in Python's zipfile module.
        if self.unsupported_compression:
            if self.carved:
                # cleanup
                os.unlink(self.temporary_file[1])
            return unpacked_files

        if not self.carved:
            unpackzipfile = zipfile.ZipFile(self.infile)
        else:
            unpackzipfile = zipfile.ZipFile(self.temporary_file[1])

        # Extract files (or create a directory for faulty files) but
        # do not yet add a file result. There are some files where
        # there are relative entries. Python's zip module will take
        # care of these entries and write in the correct place, but
        # this means that the filename from the ZIP info object cannot
        # be used.
        #
        # Examples:
        # https://github.com/iBotPeaches/Apktool/issues/1498
        # https://github.com/iBotPeaches/Apktool/issues/1589
        #
        # Test data can be found in the Apktool repository
        for z in self.zipinfolist:
            outfile_rel = self.rel_unpack_dir / z.filename
            outfile_full = self.scan_environment.unpack_path(outfile_rel)

            if z in self.faulty_files:
                # create the directory
                # TODO: check for relative paths
                outfile_full.mkdir(exist_ok=True)
            else:
                try:
                    unpackzipfile.extract(z, path=self.rel_unpack_dir)
                except NotADirectoryError:
                    # TODO: find out what to do here. This happens
                    # sometimes with zip files with symbolic links from
                    # one directory to another.
                    pass

        # Walk the result directory
        for result in unpackdir_full.glob('**/*'):
            # add the file to the result set
            file_path = result.relative_to(unpackdir_full)
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
            unpacked_files.append(fr)

        if self.carved:
            # cleanup
            os.unlink(self.temporary_file[1])

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['zip', 'compressed']
        if self.encrypted:
            labels.append('encrypted')
        if self.android_signing:
            labels.append('apk')
            labels.append('android')
        if self.dahua:
            labels.append('dahua')

        if not self.carved:
            zfile = self.infile
        else:
            zfile = self.temporary_file[1]

        unpackzipfile = zipfile.ZipFile(zfile)
        try:
            # TODO: process apk results
            apk = pyaxmlparser.APK(zfile)
        except:
            pass

        is_opc = False
        for z in self.zipinfolist:
            # https://www.python.org/dev/peps/pep-0427/
            if 'dist-info/WHEEL' in z.filename:
                labels.append('python wheel')
            # https://setuptools.readthedocs.io/en/latest/formats.html
            if z.filename == 'EGG-INFO/PKG-INFO':
                labels.append('python egg')
            if z.filename == 'AndroidManifest.xml' or z.filename == 'classes.dex':
                if self.fileresult.filename.suffix == '.apk':
                    labels.append('android')
                    labels.append('apk')

            # https://source.android.com/devices/tech/ota/apex
            if z.filename == 'apex_pubkey' and self.fileresult.filename.suffix == '.apex':
                    labels.append('android')
                    labels.append('apex')

            # https://source.android.com/devices/tech/ota/apex
            if z.filename == 'original_apex' and self.fileresult.filename.suffix == '.capex':
                    labels.append('android')
                    labels.append('compressed apex')

            # https://en.wikipedia.org/wiki/Open_Packaging_Conventions
            if z.filename == '[Content_Types].xml':
                labels.append("Open Packaging Conventions")
                is_opc = True

        if is_opc:
            for z in self.zipinfolist:
                if self.fileresult.filename.suffix == '.nupkg':
                    if z.filename.endswith('.nuspec'):
                        labels.append('nuget')
                        break

        metadata = {}
        metadata['comment'] = self.zip_comment

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
