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
import tempfile
import zipfile

import pyaxmlparser

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_zip

from . import zip as kaitai_zip

MIN_VERSION = 0
MAX_VERSION = 90

# several ZIP headers
ARCHIVE_EXTRA_DATA = b'PK\x06\x08'
CENTRAL_DIRECTORY = b'PK\x01\x02'
DATA_DESCRIPTOR = 'PK\x07\x08'
DIGITAL_SIGNATURE = b'PK\x05\x05'
END_OF_CENTRAL_DIRECTORY = b'PK\x05\x06'
LOCAL_FILE_HEADER = b'PK\x03\x04'
ZIP64_END_OF_CENTRAL_DIRECTORY = b'PK\x06\x06'
ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR = b'PK\x06\x07'


class ZipUnpackParser(WrappedUnpackParser):
#class ZipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PK\x03\04'),
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
                if s.section_type == kaitai_zip.Zip.SectionTypes.local_file:
                    local_files.append((s.body.header.file_name, s.body.header.crc32))
                    if s.body.header.flags.file_encrypted:
                        self.encrypted = True
                elif s.section_type == kaitai_zip.Zip.SectionTypes.central_dir_entry:
                    central_directory_files.append((s.body.file_name, s.body.crc32))

            # some more sanity checks here: verify if the local files
            # and the central directory (including CRC32 values) match
            if len(local_files) != len(central_directory_files):
                raise UnpackParserException("local files and central directory files do not match")
            if set(local_files) != set(central_directory_files):
                raise UnpackParserException("local files and central directory files do not match")
            self.kaitai_success = True
        except (UnpackParserException, ValidationFailedError) as e:
            self.kaitai_success = False

        # in case the file cannot be successfully unpacked
        # there is only the hard way left: parse from the start
        # and keep track of everything manually.
        if not self.kaitai_success:
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
                elif checkbytes == DATA_DESCRIPTOR:
                    check_condition(self.infile.tell() + 12 <= self.fileresult.filesize,
                                    "not enough data for data descriptor")

                    # skip the digital signature
                    self.infile.seek(12, os.SEEK_CUR)
                else:
                    # then check to see if this is possibly an Android
                    # signing block:
                    #
                    # https://source.android.com/security/apksigning/v2
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
                    if self.android_signing or checkbytes == b'\x00\x00\x00\x00' or not datadescriptor:
                        # first go back four bytes
                        self.infile.seek(-4, os.SEEK_CUR)

                        # then read 8 bytes for the APK signing block size
                        checkbytes = self.infile.read(8)
                        check_condition(len(checkbytes) == 8,
                                        "not enough data for ZIP64 end of Android signing block")

                        androidsigningsize = int.from_bytes(checkbytes, byteorder='little')

                        # as the last 16 bytes are for the Android signing block
                        # the block has to be at least 16 bytes.
                        check_condition(androidsigningsize >= 16,
                                        "wrong size for Android signing block")

                        # the signing block cannot be (partially)
                        # outside of the file
                        check_condition(self.infile.tell() + androidsigningsize <= self.fileresult.filesize,
                                        "not enough data for Android signing block")

                        # then skip over the signing block, except the
                        # last 16 bytes to have an extra sanity check
                        self.infile.seek(androidsigningsize - 16, os.SEEK_CUR)
                        checkbytes = self.infile.read(16)
                        check_condition(checkbytes == b'APK Sig Block 42',
                                        "wrong magic for Android signing block")
                        self.android_signing = True
                    else:
                        break
                continue

            # continue with the local file headers instead
            if checkbytes == localfileheader and not inlocal:
                # this should totally not happen in a valid
                # ZIP file: local file headers should not be
                # interleaved with other headers.
                #break
                pass

            # minimal version needed. According to 4.4.3.2 the minimal
            # version is 1.0 and the latest is 6.3. As new versions of
            # PKZIP could be released this check should not be too strict.
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for local file header")

            brokenzipversion = False
            minversion = int.from_bytes(checkbytes, byteorder='little')

            # some files observed in the wild have a weird version
            if minversion in [0x30a, 0x314]:
                brokenzipversion = True

            check_condition(minversion >= MIN_VERSION,
                            "invalid ZIP version %d" % minversion)

            if not brokenzipversion:
                check_condition(minversion <= MAX_VERSION,
                                "invalid ZIP version %d" % minversion)

            # then the "general purpose bit flag" (section 4.4.4)
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for general bit flag in local file header")
            generalbitflag = int.from_bytes(checkbytes, byteorder='little')

            # check if the file is encrypted. If so it should be labeled
            # as such, but not be unpacked.
            # generalbitflag & 0x40 == 0x40 would be a check for
            # strong encryption, but that has different length encryption
            # headers and right now there are no test files for it, so
            # leave it for now.
            if generalbitflag & 0x01 == 0x01:
                self.encrypted = True

            datadescriptor = False

            # see if there is a data descriptor for regular files in the
            # general purpose bit flag. This usually won't be set for
            # directories although sometimes it is
            # (example: framework/ext.jar from various Android versions)
            if generalbitflag & 0x08 == 0x08:
                datadescriptor = True

            # then the compression method (section 4.4.5)
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for compression method in local file header")
            compressionmethod = int.from_bytes(checkbytes, byteorder='little')

            # time and date fields (section 4.4.6)
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for last mod time field")

            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for last mod date field")

            # CRC32 (section 4.4.7)
            checkbytes = self.infile.read(4)
            check_condition(len(checkbytes) == 4,
                            "not enough data for CRC32 in local file header")

            # compressed size (section 4.4.8)
            checkbytes = self.infile.read(4)
            check_condition(len(checkbytes) == 4,
                            "not enough data for compressed size in local file header")

            compressedsize = int.from_bytes(checkbytes, byteorder='little')

            # uncompressed size (section 4.4.9)
            checkbytes = self.infile.read(4)
            check_condition(len(checkbytes) == 4,
                            "not enough data for uncompressed size in local file header")
            uncompressedsize = int.from_bytes(checkbytes, byteorder='little')

            # then the file name length (section 4.4.10)
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for filename length in local file header")
            filenamelength = int.from_bytes(checkbytes, byteorder='little')

            # and the extra field length (section 4.4.11)
            # There does not necessarily have to be any useful data
            # in the extra field.
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for extra field length in local file header")
            extrafieldlength = int.from_bytes(checkbytes, byteorder='little')

            localfilename = self.infile.read(filenamelength)
            check_condition(len(checkbytes) == filenamelength,
                            "not enough data for file name in local file header")
            local_files.append(localfilename)

            # then check the extra field. The most important is to check
            # for any ZIP64 extension, as it contains updated values for
            # the compressed size and uncompressed size (section 4.5)
            if extrafieldlength > 0:
                extrafields = self.infile.read(extrafieldlength)

            # then check the extra field. The most important is to check
            # for a ZIP64 extension, as it contains updated values for
            # the compressed size and uncompressed size (section 4.5)
            if extrafieldlength > 0:
                extrafields = self.infile.read(extrafieldlength)

            if extrafieldlength > 4:
                extrafieldcounter = 0
                while extrafieldcounter + 4 < extrafieldlength:
                    # section 4.6.1
                    extrafieldheaderid = int.from_bytes(extrafields[extrafieldcounter:extrafieldcounter+2], byteorder='little')

                    # often found in the first entry in JAR files and
                    # Android APK files, but not mandatory.
                    # http://hg.openjdk.java.net/jdk7/jdk7/jdk/file/00cd9dc3c2b5/src/share/classes/java/util/jar/JarOutputStream.java#l46
                    if extrafieldheaderid == 0xcafe:
                        pass

                    extrafieldheaderlength = int.from_bytes(extrafields[extrafieldcounter+2:extrafieldcounter+4], byteorder='little')
                    extrafieldcounter += 4
                    check_condition(self.infile.tell() + extrafieldheaderlength < self.fileresult.filesize,
                                    "not enough data for extra field")

                    if extrafieldheaderid == 0x001:
                        # ZIP64, section 4.5.3
                        # according to 4.4.3.2 PKZIP 4.5 or later is
                        # needed to unpack ZIP64 files.
                        check_condition(minversion >= 45, "wrong minimal needed version for ZIP64")

                        # according to the official ZIP specifications the length of the
                        # header should be 28, but there are files where this field is
                        # 16 bytes long instead, sigh...
                        check_condition(extrafieldheaderlength in [16, 28],
                                        "wrong extra field header length for ZIP64")

                        zip64uncompressedsize = int.from_bytes(extrafields[extrafieldcounter:extrafieldcounter+8], byteorder='little')
                        zip64compressedsize = int.from_bytes(extrafields[extrafieldcounter+8:extrafieldcounter+16], byteorder='little')
                        if compressedsize == 0xffffffff:
                            compressedsize = zip64compressedsize
                        if uncompressedsize == 0xffffffff:
                            uncompressedsize = zip64uncompressedsize
                    extrafieldcounter += extrafieldheaderlength

            # some sanity checks: file name, extra field and compressed
            # size cannot extend past the file size
            locallength = 30 + filenamelength + extrafieldlength + compressedsize
            if offset + locallength > filesize:
                self.infile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'data cannot be outside file'}
                return {'status': False, 'error': unpackingerror}

            # Section 4.4.4, bit 3:
            # "If this bit is set, the fields crc-32, compressed
            # size and uncompressed size are set to zero in the
            # local header.  The correct values are put in the
            # data descriptor immediately following the compressed
            # data."
            ddfound = False
            ddsearched = False

            if (not localfilename.endswith(b'/') and compressedsize == 0) or datadescriptor:
                # first store where the data possibly starts
                datastart = self.infile.tell()

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
                    curpos = self.infile.tell()
                    tmppos = -1

                    # read a number of bytes to be searched for markers
                    checkbytes = self.infile.read(50000)
                    newcurpos = self.infile.tell()
                    if checkbytes == b'':
                        break

                    # first search for the common marker for
                    # data descriptors, but only if the right
                    # flag has been set in the general purpose
                    # bit flag.
                    if datadescriptor:
                        ddpos = -1
                        while True:
                            ddpos = checkbytes.find(DATA_DESCRIPTOR, ddpos+1)
                            if ddpos != -1:
                                ddsearched = True
                                ddfound = True
                                # sanity check
                                self.infile.seek(curpos + ddpos + 8)
                                tmpcompressedsize = int.from_bytes(self.infile.read(4), byteorder='little')
                                if curpos + ddpos - datastart == tmpcompressedsize:
                                    tmppos = ddpos
                                    break
                            else:
                                break

                    # search for a local file header which indicates
                    # the next entry in the ZIP file
                    localheaderpos = checkbytes.find(LOCAL_FILE_HEADER)
                    if localheaderpos != -1 and (localheaderpos < tmppos or tmppos == -1):
                        # In case the file that is stored is an empty
                        # file, then there will be no data descriptor field
                        # so just continue as normal.
                        if curpos + localheaderpos == datastart:
                            self.infile.seek(curpos)
                            break

                        # if there is a data descriptor, then the 12
                        # bytes preceding the next header are:
                        # * crc32
                        # * compressed size
                        # * uncompressed size
                        # section 4.3.9
                        if datadescriptor:
                            if curpos + localheaderpos - datastart > 12:
                                self.infile.seek(curpos + localheaderpos - 8)
                                tmpcompressedsize = int.from_bytes(self.infile.read(4), byteorder='little')
                                # and return to the original position
                                self.infile.seek(newcurpos)
                                if curpos + localheaderpos - datastart == tmpcompressedsize + 16:
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
                    centraldirpos = checkbytes.find(CENTRAL_DIRECTORY)
                    if centraldirpos != -1:
                        # In case the file that is stored is an empty
                        # file, then there will be no data descriptor field
                        # so just continue as normal.
                        if curpos + centraldirpos == datastart:
                            self.infile.seek(curpos)
                            break

                        # if there is a data descriptor, then the 12
                        # bytes preceding the next header are:
                        # * crc32
                        # * compressed size
                        # * uncompressed size
                        # section 4.3.9
                        if datadescriptor:
                            if curpos + centraldirpos - datastart > 12:
                                self.infile.seek(curpos + centraldirpos - 8)
                                tmpcompressedsize = int.from_bytes(self.infile.read(4), byteorder='little')
                                # and return to the original position
                                self.infile.seek(newcurpos)
                                if curpos + centraldirpos - datastart == tmpcompressedsize + 16:
                                    if tmppos == -1:
                                        tmppos = centraldirpos
                                    else:
                                        tmppos = min(centraldirpos, tmppos)
                                else:
                                    if curpos + centraldirpos - datastart > 16:
                                        self.infile.seek(curpos + centraldirpos - 16)
                                        tmpbytes = self.infile.read(16)
                                        if tmpbytes == b'APK Sig Block 42':
                                            androidsigning = True
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
                        self.infile.seek(curpos + tmppos + 42)
                        checkfn = self.infile.read(filenamelength)
                        if localfilename != checkfn:
                            tmppos = oldtmppos
                        self.infile.seek(origpos)
                    if tmppos != -1:
                        self.infile.seek(curpos + tmppos)
                        break

                    # have a small overlap the size of a possible header
                    # unless it is the last 4 bytes of the file
                    if self.infile.tell() == filesize:
                        break
                    self.infile.seek(-4, os.SEEK_CUR)
            else:
                check_condition(self.infile.tell() + compressedsize <= self.fileresult.filesize,
                                "not enough data for compressed data")
                self.infile.seek(self.infile.tell() + compressedsize)

        self.unpacked_size = self.infile.tell()

        # If the ZIP file is at the end of the file then the ZIP module
        # from Python will do a lot of the heavy lifting. If not it first
        # needs to be carved.
        #
        # Malformed ZIP files that need a workaround exist:
        # http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442
        if self.unpacked_size == self.fileresult.filesize:
            self.carved = False
        else:
            # else carve the file from the larger ZIP first
            self.temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(self.temporary_file[0]).close()
            self.carved = True

        if not self.carved:
            # seek to the right offset, even though that's
            # probably not necessary.
            self.infile.seek(0)

        # store if an unsupported compression was found
        self.unsupported_compression = False

        # Malformed ZIP files where directories are stored as normal files exist:
        # http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442
        self.faulty_files = []

        try:
            if not self.carved:
                unpackzipfile = zipfile.ZipFile(self.infile)
            else:
                unpackzipfile = zipfile.ZipFile(self.temporary_file[1])
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

        except zipfile.BadZipFile as e:
            if self.carved:
                # cleanup
                os.unlink(self.temporary_file[1])
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        unpacked_files = []

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

        if self.faulty_files == []:
            pass
        else:
            for z in self.zipinfolist:
                outfile_rel = self.rel_unpack_dir / z.filename
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)

                if z in self.faulty_files:
                    # create the directory
                    outfile_full.mkdir(exist_ok=True)
                    fr = FileResult(self.fileresult, outfile_rel, set())
                    unpacked_files.append(fr)
                else:
                    unpackzipfile.extract(z, path=self.rel_unpack_dir)
                    fr = FileResult(self.fileresult, outfile_rel, set())
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

        if not self.carved:
            unpackzipfile = zipfile.ZipFile(self.infile)
        else:
            unpackzipfile = zipfile.ZipFile(self.temporary_file[1])

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

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
