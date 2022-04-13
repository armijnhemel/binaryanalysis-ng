#!/usr/bin/env python3

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
# Copyright 2018-2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# Built in carvers/verifiers/unpackers for various formats.
#
# For these unpackers it has been attempted to reduce disk I/O as much
# as possible using the os.sendfile() method, as well as techniques
# described in this blog post:
#
# https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import os
import binascii
import tempfile
import collections
import lzma
import zlib
import zipfile
import bz2
import re
import xml.dom
import hashlib

# some external packages that are needed
import defusedxml.minidom
import pyaxmlparser


# Each unpacker has a specific interface:
#
# def unpacker(fileresult, scanenvironment, offset, unpackdir):
#
# * fileresult: the fileresult so far
# * scanenvironment: the scanenvironment
# * offset: offset inside the file where the file system, compressed
#   file media file possibly starts
# * unpackdir: the target directory where data should be written to as
#   a relative path
#
# The unpackers are supposed to return a dictionary with the following
# field:
#
# * unpack status (boolean) to indicate whether or not any data was
#   unpacked
#
# Depending on the value of the status several other fields are
# expected. For successful scans (unpack status == True) the following
# should be present:
#
# * unpack size to indicate what part of the data was unpacked
# * a list of tuples (file, labels) that were unpacked from the file.
#   The labels could be used to indicate that a file has a certain
#   status and that it should not be unpacked as it is already known
#   what the file is (example: PNG)
# * a list of labels for the file
# * a dict with extra information (structure depending on type
#   of scan)
# * (optional) offset indicating the start of the data
#
# If the scan was unsuccessful (unpack status == False), the following
# should be present:
#
# * a dict with a possible error.
#
# The error dict has the following items:
#
# * fatal: boolean to indicate whether or not the error is a fatal
#   error (such as disk full, etc.) so BANG should be stopped.
#   Non-fatal errors are format violations (files, etc.)
# * offset: offset where the error occured
# * reason: human readable description of the error


# Dahua is a Chinese vendor that is using the ZIP format for its firmware
# updates, but has changed the first two characters of the file from PK to DH
def unpack_dahua(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack modified ZIP compressed data from Dahua.'''
    filename_full = scanenvironment.unpack_path(fileresult.filename)

    # first change the header
    checkfile = open(filename_full, 'r+b')

    # seek to the offset and change the identifier
    # from DH to PK
    checkfile.seek(offset)
    checkfile.write(b'PK')
    checkfile.close()

    dahuares = unpack_zip(fileresult, scanenvironment, offset, unpackdir)

    # reopen for writing
    checkfile = open(filename_full, 'r+b')

    # seek to the offset and change the identifier
    # back from PK to DH
    checkfile.seek(offset)
    checkfile.write(b'DH')
    checkfile.close()

    if dahuares['status']:
        dahuares['labels'].append('dahua')
    return dahuares

# http://web.archive.org/web/20190709133846/https://ipcamtalk.com/threads/dahua-ipc-easy-unbricking-recovery-over-tftp.17189/page-2
unpack_dahua.signatures = {'dahua': b'DH\x03\04'}
unpack_dahua.minimum_size = 30


# https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
# Documenting version 6.3.6
# This method first verifies a file to see where the ZIP data
# starts and where it ends.
#
# Python's zipfile module starts looking at the end of the file
# for a central directory. If multiple ZIP files have been concatenated
# and the last ZIP file is at the end, then only this ZIP file
# will be unpacked by Python's zipfile module.
#
# A description of some of the underlying problems encountered
# when writing this code can be found here:
#
# http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html
def unpack_zip(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack ZIP compressed data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # the ZIP file format is described in section 4.3.6
    # the header is at least 30 bytes
    if filesize < 30:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    encrypted = False
    zip64 = False

    # skip over the (local) magic
    # and process like section 4.3.7
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    minzipversion = 0
    maxzipversion = 90

    seencentraldirectory = False
    inlocal = True
    seenzip64endofcentraldir = False

    # store if there is an Android signing block:
    # https://source.android.com/security/apksigning/v2
    androidsigning = False

    # store the local file names to check if they appear in the
    # central directory in the same order (optional)
    localfiles = []
    centraldirectoryfiles = []

    localfileheader = b'\x50\x4b\x03\x04'

    seenfirstheader = False

    # First there are file entries, followed by a central
    # directory, possibly with other headers following/preceding
    while True:
        # first read the header
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ZIP entry header'}
            return {'status': False, 'error': unpackingerror}

        # process everything that is not a local file header, but
        # either a ZIP header or an Android signing signature.
        if checkbytes != localfileheader:
            inlocal = False
            unpackedsize += 4

            # archive decryption header
            # archive data extra field (section 4.3.11)
            if checkbytes == b'\x50\x4b\x06\x08':
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for archive decryption header field'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 4
                archivedecryptionsize = int.from_bytes(checkbytes, byteorder='little')
                if checkfile.tell() + archivedecryptionsize > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for archive decryption header field'}
                    return {'status': False, 'error': unpackingerror}
                checkfile.seek(archivedecryptionsize, os.SEEK_CUR)
                unpackedsize += archivedecryptionsize
            # check for the start of the central directory (section 4.3.12)
            elif checkbytes == b'\x50\x4b\x01\02':
                seencentraldirectory = True
                if checkfile.tell() + 46 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for end of central directory'}
                    return {'status': False, 'error': unpackingerror}

                # skip 24 bytes in the header to the file name
                # and extra field
                checkfile.seek(24, os.SEEK_CUR)
                unpackedsize += 24

                # read the file name
                checkbytes = checkfile.read(2)
                filenamelength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                # read the extra field length
                checkbytes = checkfile.read(2)
                extrafieldlength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                # read the file comment length
                checkbytes = checkfile.read(2)
                filecommentlength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                # skip 12 bytes in the central directory header
                checkfile.seek(12, os.SEEK_CUR)
                unpackedsize += 12

                # read the file name
                checkbytes = checkfile.read(filenamelength)
                if len(checkbytes) != filenamelength:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for file name in central directory'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += filenamelength
                centraldirectoryfiles.append(checkbytes)

                if extrafieldlength != 0:
                    # read the extra field
                    checkbytes = checkfile.read(extrafieldlength)
                    if len(checkbytes) != extrafieldlength:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for extra field in central directory'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += extrafieldlength

                if filecommentlength != 0:
                    # read the file comment
                    checkbytes = checkfile.read(filecommentlength)
                    if len(checkbytes) != filecommentlength:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for extra field in central directory'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += filecommentlength

            # check for digital signatures (section 4.3.13)
            elif checkbytes == b'\x50\x4b\x05\x05':
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for digital signature size field'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2
                digitalsignaturesize = int.from_bytes(checkbytes, byteorder='little')
                if checkfile.tell() + digitalsignaturesize > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for digital signature'}
                    return {'status': False, 'error': unpackingerror}
                checkfile.seek(digitalsignaturesize, os.SEEK_CUR)
                unpackedsize += digitalsignaturesize

            # check for ZIP64 end of central directory (section 4.3.14)
            elif checkbytes == b'\x50\x4b\x06\x06':
                if not seencentraldirectory:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'ZIP64 end of cental directory, but no central directory header'}
                    return {'status': False, 'error': unpackingerror}
                seenzip64endofcentraldir = True

                # first read the size of the ZIP64 end of
                # central directory (section 4.3.14.1)
                checkbytes = checkfile.read(8)
                if len(checkbytes) != 8:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for ZIP64 end of central directory header'}
                    return {'status': False, 'error': unpackingerror}

                zip64endofcentraldirectorylength = int.from_bytes(checkbytes, byteorder='little')
                if checkfile.tell() + zip64endofcentraldirectorylength > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for ZIP64 end of central directory'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 8

                # now skip over the rest of the data in the
                # ZIP64 end of central directory
                checkfile.seek(zip64endofcentraldirectorylength, os.SEEK_CUR)
                unpackedsize += zip64endofcentraldirectorylength

            # check for ZIP64 end of central directory locator
            # (section 4.3.15)
            elif checkbytes == b'\x50\x4b\x06\x07':
                if not seenzip64endofcentraldir:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'ZIP64 end of cental directory locator, but no ZIP64 end of central directory'}
                    return {'status': False, 'error': unpackingerror}
                if checkfile.tell() + 16 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for ZIP64 end of central directory locator'}
                    return {'status': False, 'error': unpackingerror}
                # skip over the data
                checkfile.seek(16, os.SEEK_CUR)
                unpackedsize += 16

            # check for end of central directory (section 4.3.16)
            elif checkbytes == b'\x50\x4b\x05\x06':
                if not seencentraldirectory:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'end of cental directory, but no central directory header'}
                    return {'status': False, 'error': unpackingerror}

                if checkfile.tell() + 18 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for end of central directory header'}
                    return {'status': False, 'error': unpackingerror}

                # skip 16 bytes of the header
                checkfile.seek(16, os.SEEK_CUR)
                unpackedsize += 16

                # read the ZIP comment length
                checkbytes = checkfile.read(2)
                zipcommentlength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2
                if zipcommentlength != 0:
                    # read the file comment
                    checkbytes = checkfile.read(zipcommentlength)
                    if len(checkbytes) != zipcommentlength:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for extra field in central directory'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += zipcommentlength
                # end of ZIP file reached, so break out of the loop
                break
            elif checkbytes == b'PK\x07\x08':
                if checkfile.tell() + 12 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for data descriptor'}
                    return {'status': False, 'error': unpackingerror}
                checkfile.seek(12, os.SEEK_CUR)
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
                if androidsigning or checkbytes == b'\x00\x00\x00\x00' or not datadescriptor:
                    # first go back four bytes
                    checkfile.seek(-4, os.SEEK_CUR)
                    unpackedsize = checkfile.tell() - offset

                    # then read 8 bytes for the APK signing block size
                    checkbytes = checkfile.read(8)
                    if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for Android signing block'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += 8
                    androidsigningsize = int.from_bytes(checkbytes, byteorder='little')

                    # APK signing V3 might pad to 4096 bytes first,
                    # introduced in:
                    #
                    # https://android.googlesource.com/platform/tools/apksig/+/edf96cb79f533eb4255ee1b6aa2ba8bf9c1729b2
                    if androidsigningsize == 0:
                        checkfile.seek(4096 - unpackedsize % 4096, os.SEEK_CUR)
                        unpackedsize += 4096 - unpackedsize % 4096

                        # then read 8 bytes for the APK signing block size
                        checkbytes = checkfile.read(8)
                        if len(checkbytes) != 8:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'not enough data for Android signing block'}
                            return {'status': False, 'error': unpackingerror}
                        unpackedsize += 8
                        androidsigningsize = int.from_bytes(checkbytes, byteorder='little')

                    # as the last 16 bytes are for the Android signing block
                    # the block has to be at least 16 bytes.
                    if androidsigningsize < 16:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'wrong size for Android signing block'}
                        return {'status': False, 'error': unpackingerror}

                    # the signing block cannot be (partially)
                    # outside of the file
                    if checkfile.tell() + androidsigningsize > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for Android signing block'}
                        return {'status': False, 'error': unpackingerror}

                    # then skip over the signing block, except the
                    # last 16 bytes to have an extra sanity check
                    checkfile.seek(androidsigningsize - 16, os.SEEK_CUR)
                    checkbytes = checkfile.read(16)
                    if checkbytes != b'APK Sig Block 42':
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'wrong magic for Android signing block'}
                        return {'status': False, 'error': unpackingerror}
                    androidsigning = True
                    unpackedsize += androidsigningsize
                else:
                    break
            continue

        # continue with the local file headers instead
        if checkbytes == localfileheader and not inlocal:
            # this should totally not happen in a valid
            # ZIP file: local file headers should not be
            # interleaved with other headers.
            break

        unpackedsize += 4

        # minimal version needed. According to 4.4.3.2 the minimal
        # version is 1.0 and the latest is 6.3. As new versions of
        # PKZIP could be released this check should not be too strict.
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for local file header'}
            return {'status': False, 'error': unpackingerror}
        brokenzipversion = False
        minversion = int.from_bytes(checkbytes, byteorder='little')

        # some files observed in the wild have a weird version
        if minversion in [0x30a, 0x314]:
            brokenzipversion = True

        if minversion < minzipversion:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid ZIP version %d' % minversion}
            return {'status': False, 'error': unpackingerror}

        if not brokenzipversion:
            if minversion > maxzipversion:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid ZIP version %d' % minversion}
                return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        # then the "general purpose bit flag" (section 4.4.4)
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for general bit flag in local file header'}
            return {'status': False, 'error': unpackingerror}
        generalbitflag = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        # check if the file is encrypted. If so it should be labeled
        # as such, but not be unpacked.
        # generalbitflag & 0x40 == 0x40 would be a check for
        # strong encryption, but that has different length encryption
        # headers and right now there are no test files for it, so
        # leave it for now.
        if generalbitflag & 0x01 == 0x01:
            encrypted = True

        datadescriptor = False

        # see if there is a data descriptor for regular files in the
        # general purpose bit flag. This usually won't be set for
        # directories although sometimes it is
        # (example: framework/ext.jar from various Android versions)
        if generalbitflag & 0x08 == 0x08:
            datadescriptor = True

        # then the compression method (section 4.4.5)
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for compression method in local file header'}
            return {'status': False, 'error': unpackingerror}
        compressionmethod = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        # skip over the time fields (section 4.4.6)
        checkfile.seek(4, os.SEEK_CUR)
        if checkfile.tell() + 4 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for time fields in local file header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # skip over the CRC32 (section 4.4.7)
        if checkfile.tell() + 4 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for CRC32 in local file header'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(4, os.SEEK_CUR)
        unpackedsize += 4

        # compressed size (section 4.4.8)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for compressed size in local file header'}
            return {'status': False, 'error': unpackingerror}
        compressedsize = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        # uncompressed size (section 4.4.9)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for uncompressed size file header'}
            return {'status': False, 'error': unpackingerror}
        uncompressedsize = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        # then the file name length (section 4.4.10)
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for filename length in local file header'}
            return {'status': False, 'error': unpackingerror}
        filenamelength = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        # and the extra field length (section 4.4.11)
        # There does not necessarily have to be any useful data
        # in the extra field.
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for extra field length in local file header'}
            return {'status': False, 'error': unpackingerror}
        extrafieldlength = int.from_bytes(checkbytes, byteorder='little')

        unpackedsize += 2

        localfilename = checkfile.read(filenamelength)
        if len(localfilename) != filenamelength:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for file name in local file header'}
            return {'status': False, 'error': unpackingerror}
        localfiles.append(localfilename)
        unpackedsize += filenamelength

        # then check the extra field. The most important is to check
        # for any ZIP64 extension, as it contains updated values for
        # the compressed size and uncompressed size (section 4.5)
        if extrafieldlength > 0:
            extrafields = checkfile.read(extrafieldlength)
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
                if checkfile.tell() + extrafieldheaderlength > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for extra field'}
                    return {'status': False, 'error': unpackingerror}
                if extrafieldheaderid == 0x001:
                    # ZIP64, section 4.5.3
                    # according to 4.4.3.2 PKZIP 4.5 or later is
                    # needed to unpack ZIP64 files.
                    if minversion < 45:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'wrong minimal needed version for ZIP64'}
                        return {'status': False, 'error': unpackingerror}
                    # according to the official ZIP specifications the length of the
                    # header should be 28, but there are files where this field is
                    # 16 bytes long instead, sigh...
                    if extrafieldheaderlength not in [16, 28]:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'wrong extra field header length for ZIP64'}
                        return {'status': False, 'error': unpackingerror}
                    zip64uncompressedsize = int.from_bytes(extrafields[extrafieldcounter:extrafieldcounter+8], byteorder='little')
                    zip64compressedsize = int.from_bytes(extrafields[extrafieldcounter+8:extrafieldcounter+16], byteorder='little')
                    if compressedsize == 0xffffffff:
                        compressedsize = zip64compressedsize
                    if uncompressedsize == 0xffffffff:
                        uncompressedsize = zip64uncompressedsize
                extrafieldcounter += extrafieldheaderlength
        unpackedsize += extrafieldlength

        # some sanity checks: file name, extra field and compressed
        # size cannot extend past the file size
        locallength = 30 + filenamelength + extrafieldlength + compressedsize
        if offset + locallength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'data cannot be outside file'}
            return {'status': False, 'error': unpackingerror}

        # keep track of if a data descriptor was searched and found
        # This is needed if the length of the compressed size is set
        # to 0, which can happen in certain cases (section 4.4.4, bit 3)
        ddfound = False
        ddsearched = False

        if (not localfilename.endswith(b'/') and compressedsize == 0) or datadescriptor:
            # first store where the data possibly starts
            datastart = checkfile.tell()

            # In case the length is not known it is very difficult
            # to see where the data ends so it is needed to search for
            # a signature. This can either be:
            #
            # * data descriptor header
            # * local file header
            # * central directory header
            #
            # Whichever is found first will be processed.
            while True:
                # store the current position of the pointer in the file
                curpos = checkfile.tell()
                tmppos = -1

                # read a number of bytes to be searched for markers
                checkbytes = checkfile.read(50000)
                newcurpos = checkfile.tell()
                if checkbytes == b'':
                    break

                # first search for the common marker for
                # data descriptors, but only if the right
                # flag has been set in the general purpose
                # bit flag.
                if datadescriptor:
                    ddpos = -1
                    while True:
                        ddpos = checkbytes.find(b'PK\x07\x08', ddpos+1)
                        if ddpos != -1:
                            ddsearched = True
                            ddfound = True
                            # sanity check
                            checkfile.seek(curpos + ddpos + 8)
                            tmpcompressedsize = int.from_bytes(checkfile.read(4), byteorder='little')
                            if curpos + ddpos - datastart == tmpcompressedsize:
                                tmppos = ddpos
                                break
                        else:
                            break

                # search for a local file header which indicates
                # the next entry in the ZIP file
                localheaderpos = checkbytes.find(b'PK\x03\x04')
                if localheaderpos != -1 and (localheaderpos < tmppos or tmppos == -1):
                    # In case the file that is stored is an empty
                    # file, then there will be no data descriptor field
                    # so just continue as normal.
                    if curpos + localheaderpos == datastart:
                        checkfile.seek(curpos)
                        break

                    # if there is a data descriptor, then the 12
                    # bytes preceding the next header are:
                    # * crc32
                    # * compressed size
                    # * uncompressed size
                    # section 4.3.9
                    if datadescriptor:
                        if curpos + localheaderpos - datastart > 12:
                            checkfile.seek(curpos + localheaderpos - 8)
                            tmpcompressedsize = int.from_bytes(checkfile.read(4), byteorder='little')
                            # and return to the original position
                            checkfile.seek(newcurpos)
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
                    checkfile.seek(newcurpos)

                # then search for the start of the central directory
                centraldirpos = checkbytes.find(b'PK\x01\x02')
                if centraldirpos != -1:
                    # In case the file that is stored is an empty
                    # file, then there will be no data descriptor field
                    # so just continue as normal.
                    if curpos + centraldirpos == datastart:
                        checkfile.seek(curpos)
                        break

                    # if there is a data descriptor, then the 12
                    # bytes preceding the next header are:
                    # * crc32
                    # * compressed size
                    # * uncompressed size
                    # section 4.3.9
                    if datadescriptor:
                        if curpos + centraldirpos - datastart > 12:
                            checkfile.seek(curpos + centraldirpos - 8)
                            tmpcompressedsize = int.from_bytes(checkfile.read(4), byteorder='little')
                            # and return to the original position
                            checkfile.seek(newcurpos)
                            if curpos + centraldirpos - datastart == tmpcompressedsize + 16:
                                if tmppos == -1:
                                    tmppos = centraldirpos
                                else:
                                    tmppos = min(centraldirpos, tmppos)
                            else:
                                if curpos + centraldirpos - datastart > 16:
                                    checkfile.seek(curpos + centraldirpos - 16)
                                    tmpbytes = checkfile.read(16)
                                    if tmpbytes == b'APK Sig Block 42':
                                        androidsigning = True
                                    # and (again) return to the
                                    # original position
                                    checkfile.seek(newcurpos)
                    else:
                        if tmppos == -1:
                            tmppos = centraldirpos
                        else:
                            tmppos = min(centraldirpos, tmppos)

                    checkfile.seek(newcurpos)

                    oldtmppos = tmppos
                    # extra sanity check: see if the
                    # file names are the same
                    origpos = checkfile.tell()
                    checkfile.seek(curpos + tmppos + 42)
                    checkfn = checkfile.read(filenamelength)
                    if localfilename != checkfn:
                        tmppos = oldtmppos
                    checkfile.seek(origpos)
                if tmppos != -1:
                    checkfile.seek(curpos + tmppos)
                    break

                # have a small overlap the size of a possible header
                # unless it is the last 4 bytes of the file
                if checkfile.tell() == filesize:
                    break
                checkfile.seek(-4, os.SEEK_CUR)
        else:
            if checkfile.tell() + compressedsize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for compressed data'}
                return {'status': False, 'error': unpackingerror}
            checkfile.seek(checkfile.tell() + compressedsize)

        unpackedsize = checkfile.tell() - offset

        # data descriptor follows the file data
        # * crc32
        # * compressed size
        # * uncompressed size
        # section 4.3.9
        if datadescriptor and ddsearched and ddfound:
            possiblesignature = checkfile.read(4)
            if possiblesignature == b'PK\x07\x08':
                ddcrc = checkfile.read(4)
            else:
                ddcrc = possiblesignature
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for compressed data field'}
                return {'status': False, 'error': unpackingerror}
            ddcompressedsize = int.from_bytes(checkbytes, byteorder='little')
            unpackedsize += 4
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for uncompressed data field'}
                return {'status': False, 'error': unpackingerror}
            dduncompressedsize = int.from_bytes(checkbytes, byteorder='little')
            if uncompressedsize != 0:
                # possibly do an extra sanity check here with the
                # compressed and/or uncompressed size fields
                pass

    if not seencentraldirectory:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'no central directory found'}
        return {'status': False, 'error': unpackingerror}

    # there should be as many entries in the local headers as in
    # the central directory
    if len(localfiles) != len(centraldirectoryfiles):
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'mismatch between local file headers and central directory'}
        return {'status': False, 'error': unpackingerror}

    # compute the difference between the local files and
    # the ones in the central directory
    # TODO: does this mean: localfiles not a subset of centraldirectoryfiles?
    if len(set(localfiles).intersection(set(centraldirectoryfiles))) != len(set(localfiles)):
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'mismatch between names in local file headers and central directory'}
        return {'status': False, 'error': unpackingerror}

    metadata = {}

    unpackedsize = checkfile.tell() - offset
    if not encrypted:
        # if the ZIP file is at the end of the file then the ZIP module
        # from Python will do a lot of the heavy lifting.
        # Malformed ZIP files that need a workaround exist:
        # http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442
        if checkfile.tell() == filesize:
            carved = False
        else:
            # else carve the file from the larger ZIP first
            temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
            os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
            os.fdopen(temporaryfile[0]).close()
            carved = True
        if not carved:
            # seek to the right offset, even though that's
            # not even necessary.
            checkfile.seek(offset)

        try:
            if not carved:
                unpackzipfile = zipfile.ZipFile(checkfile)
            else:
                unpackzipfile = zipfile.ZipFile(temporaryfile[1])
            zipfiles = unpackzipfile.namelist()
            zipinfolist = unpackzipfile.infolist()
            oldcwd = os.getcwd()

            # create the unpacking directory
            os.makedirs(unpackdir_full, exist_ok=True)
            os.chdir(unpackdir_full)
            knowncompression = True

            # check if there have been directories stored
            # as regular files.
            faultyzipfiles = []
            is_opc = False
            for z in zipinfolist:
                # https://www.python.org/dev/peps/pep-0427/
                if 'dist-info/WHEEL' in z.filename:
                    labels.append('python wheel')
                # https://setuptools.readthedocs.io/en/latest/formats.html
                if z.filename == 'EGG-INFO/PKG-INFO':
                    labels.append('python egg')
                if z.filename == 'AndroidManifest.xml' or z.filename == 'classes.dex':
                    if filename_full.suffix == '.apk':
                        labels.append('android')
                        labels.append('apk')

                # https://en.wikipedia.org/wiki/Open_Packaging_Conventions
                if z.filename == '[Content_Types].xml':
                    labels.append("Open Packaging Conventions")
                    is_opc = True
                if z.file_size == 0 and not z.is_dir() and z.external_attr & 0x10 == 0x10:
                    faultyzipfiles.append(z)
                # only stored, deflate, bzip2 and lzma are supported
                # in Python's zipfile module.
                if z.compress_type not in [0, 8, 12, 14]:
                    knowncompression = False
                    break
            if knowncompression:
                for z in zipinfolist:
                    if filename_full.suffix == '.nupkg' and is_opc:
                        if z.filename.endswith('.nuspec'):
                            labels.append('NuGet')
                            break
            if knowncompression:
                if faultyzipfiles == []:
                    try:
                        unpackzipfile.extractall()
                    except NotImplementedError:
                        checkfile.close()
                        if carved:
                            os.unlink(temporaryfile[1])
                        unpackingerror = {'offset': offset, 'fatal': False,
                                          'reason': 'Unknown compression method'}
                        return {'status': False, 'error': unpackingerror}
                    except NotADirectoryError:
                        # TODO: find out what to do with this. This happens
                        # sometimes with zip files with symbolic links from
                        # one directory to another.
                        pass
                else:
                    for z in zipinfolist:
                        if z in faultyzipfiles:
                            # create the directory
                            zdirname_full = scanenvironment.unpack_path(os.path.join(unpackdir, z.filename))
                            os.makedirs(zdirname_full, exist_ok=True)
                        else:
                            unpackzipfile.extract(z)
            os.chdir(oldcwd)
            unpackzipfile.close()

            if knowncompression:
                dirwalk = os.walk(unpackdir_full)
                for entry in dirwalk:
                    for direntry in entry[1]:
                        fn = scanenvironment.rel_unpack_path(
                            os.path.join(entry[0], direntry))
                        unpackedfilesandlabels.append((fn, []))
                    for direntry in entry[2]:
                        fn = scanenvironment.rel_unpack_path(
                            os.path.join(entry[0], direntry))
                        unpackedfilesandlabels.append((fn, []))
            else:
                labels.append("unknown compression")

            if offset == 0 and not carved:
                labels.append('compressed')
                labels.append('zip')
                if androidsigning:
                    labels.append('apk')
                    labels.append('android')
                if 'apk' in labels:
                    try:
                        apk = pyaxmlparser.APK(filename_full)
                    except:
                        pass
            if carved:
                os.unlink(temporaryfile[1])
            checkfile.close()
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels,
                    'metadata': metadata}
        except zipfile.BadZipFile:
            checkfile.close()
            if carved:
                os.unlink(temporaryfile[1])
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'Not a valid ZIP file'}
            return {'status': False, 'error': unpackingerror}

    # it is an encrypted file
    if offset == 0 and checkfile.tell() == filesize:
        checkfile.close()
        labels.append('compressed')
        labels.append('zip')
        labels.append('encrypted')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels,
                'metadata': metadata}

    # else carve the file
    targetfile_rel = os.path.join(unpackdir, 'encrypted.zip')
    targetfile_full = scanenvironment.unpack_path(targetfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    targetfile = open(targetfile_full, 'wb')
    os.sendfile(targetfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    targetfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((targetfile_rel, ['encrypted', 'zip', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels,
            'metadata': metadata}

# https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT section 4.3.6
unpack_zip.signatures = {'zip': b'\x50\x4b\x03\04'}
unpack_zip.minimum_size = 30


# Derived from specifications at:
# https://github.com/mackyle/xar/wiki/xarformat
#
# Basically XAR is a header, a zlib compressed XML file describing
# where to find files and how they were compressed, and then the
# actual data (perhaps compressed).
#
# Compression depends on the options provided and the version of XAR being
# used. Fedora's standard version uses:
#
# * none
# * gzip (default, but it is actually zlib's DEFLATE)
# * bzip2
#
# Other versions (from Git) can also use:
# * xz
# * lzma
def unpack_xar(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a XAR archive.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize - offset < 28:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Too small for XAR file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename_full, 'rb')

    # skip over the file magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    # read the size field
    checkbytes = checkfile.read(2)
    headersize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    # read the version field
    checkbytes = checkfile.read(2)
    unpackedsize += 2

    # read the toc_length_compressed field
    checkbytes = checkfile.read(8)
    toc_length_compressed = int.from_bytes(checkbytes, byteorder='big')

    # check that the table of contents (toc) is actually
    # inside the file
    if offset + headersize + toc_length_compressed > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'file too small'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # read the toc_length_uncompressed field. Use this for
    # sanity checking.
    checkbytes = checkfile.read(8)
    unpackedsize += 8
    toc_length_uncompressed = int.from_bytes(checkbytes, byteorder='big')

    # read the cksum_alg field. In case it is 3 do some extra
    # sanity checks.
    checkbytes = checkfile.read(4)
    checksumalgorithm = int.from_bytes(checkbytes, byteorder='big')
    if checksumalgorithm == 3:
        if filesize - offset < 32:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False, 'reason': 'file too small'}
            return {'status': False, 'error': unpackingerror}
        if headersize < 32:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False, 'reason': 'header too small'}
            return {'status': False, 'error': unpackingerror}
        if headersize % 4 != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'header not 4 byte aligned'}
            return {'status': False, 'error': unpackingerror}
    else:
        # all the other checksum algorithms have a 28 byte header
        if headersize != 28:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong header size'}
            return {'status': False, 'error': unpackingerror}

    # skip over the entire header
    checkfile.seek(offset+headersize)
    unpackedsize = headersize

    # read the table of contents
    checkbytes = checkfile.read(toc_length_compressed)
    # now decompress the table of contents
    try:
        toc = zlib.decompress(checkbytes)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'cannot decompress table of contents'}
        return {'status': False, 'error': unpackingerror}
    if len(toc) != toc_length_uncompressed:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'table of contents length does not match header'}
        return {'status': False, 'error': unpackingerror}

    # the toc is an XML file, so parse it
    try:
        tocdom = defusedxml.minidom.parseString(toc)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'table of contents is not valid XML'}
        return {'status': False, 'error': unpackingerror}

    # The interesting information is in the <file> element. As these
    # can be nested (to resemble a directory tree) each element has
    # to be looked at separately to see if there are any child elements
    # that have files or other directories.

    # The top level element should be <xar>
    if tocdom.documentElement.tagName != 'xar':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'table of contents is not a valid TOC for XAR'}
        return {'status': False, 'error': unpackingerror}

    # there should be one single node called "toc". If not, it
    # is a malformed XAR table of contents.
    havevalidtoc = False
    for i in tocdom.documentElement.childNodes:
        # the childnodes of the element could also
        # include text nodes, which are not interesting
        if i.nodeType == xml.dom.Node.ELEMENT_NODE:
            if i.tagName == 'toc':
                havevalidtoc = True
                tocnode = i
                break

    if not havevalidtoc:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'table of contents is not a valid TOC for XAR'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize += toc_length_compressed

    # Then further traverse the DOM
    # Since each element only has relative path information it is
    # necessary to keep track of the directory structure.

    maxoffset = -1

    # store the nodes to traverse from the DOM in a deque, and then
    # pop from the left as it is much more efficient then using a list
    # for that.
    # First fill up the deque with the top level file nodes.
    nodestotraverse = collections.deque()
    for i in tocnode.childNodes:
        if i.nodeType == xml.dom.Node.ELEMENT_NODE:
            if i.tagName == 'file':
                nodestotraverse.append((i, ''))
            elif i.tagName == 'checksum':
                # top level checksum should have a size field and offset
                for ic in i.childNodes:
                    if ic.nodeType == xml.dom.Node.ELEMENT_NODE:
                        if ic.tagName == 'offset':
                            # traverse the child nodes
                            for dd in ic.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    checksumoffset = dd.data.strip()
                        elif ic.tagName == 'size':
                            # traverse the child nodes
                            for dd in ic.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    checksumsize = dd.data.strip()
                try:
                    checksumoffset = int(checksumoffset)
                    checksumsize = int(checksumsize)
                except ValueError:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'XML bogus values'}
                    return {'status': False, 'error': unpackingerror}
                # the checksum cannot be outside of the file
                if offset + unpackedsize + checksumoffset + checksumsize > filesize:
                    targetfile.close()
                    os.unlink(targetfilename)
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data'}
                    return {'status': False, 'error': unpackingerror}
                maxoffset = max(maxoffset, offset + unpackedsize + checksumoffset + checksumsize)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    while len(nodestotraverse) != 0:
        (nodetoinspect, nodecwd) = nodestotraverse.popleft()

        # then inspect the contents of the node. Since it is not
        # guaranteed in which order the elements appear in the XML
        # file some information has to be kept first.
        nodename = None
        nodetype = None
        nodedata = None
        childfilenodes = []
        for i in nodetoinspect.childNodes:
            if i.nodeType == xml.dom.Node.ELEMENT_NODE:
                if i.tagName == 'type':
                    # first find out if it is a file, or a directory
                    for cn in i.childNodes:
                        if cn.nodeType == xml.dom.Node.TEXT_NODE:
                            nodetype = cn.data.strip()
                    # something went wrong here
                    if nodetype is None:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'missing file type in TOC'}
                        return {'status': False, 'error': unpackingerror}
                elif i.tagName == 'name':
                    # grab the name of the entry and store it in
                    # nodename.
                    for cn in i.childNodes:
                        if cn.nodeType == xml.dom.Node.TEXT_NODE:
                            nodename = cn.data.strip()
                elif i.tagName == 'file':
                    # add children to be processed
                    childfilenodes.append(i)
                elif i.tagName == 'data':
                    # any data that might be there for the file
                    nodedata = i

        # remove any superfluous / characters. This should not happen
        # with XAR but just in case...
        while nodename.startswith('/'):
            nodename = nodename[1:]

        if nodetype == 'directory':
            os.makedirs(os.path.join(unpackdir_full, nodecwd, nodename))
        elif nodetype == 'file':
            # first create the file
            targetfile_rel = os.path.join(unpackdir, nodecwd, nodename)
            targetfile_full = scanenvironment.unpack_path(targetfile_rel)
            targetfile = open(targetfile_full, 'wb')
            if nodedata is not None:
                # extract the data for the file:
                # * compression method (called "encoding")
                # * offset
                # * length
                # * archived checksum + type (compressed data)
                # * extracted checksum + type (uncompressed data)
                compressionmethod = None
                datalength = 0  # compressed
                datasize = 0  # uncompressed
                dataoffset = 0
                archivedchecksum = None
                archivedchecksumtype = None
                extractedchecksum = None
                extractedchecksumtype = None
                for d in nodedata.childNodes:
                    if d.nodeType == xml.dom.Node.ELEMENT_NODE:
                        if d.tagName == 'encoding':
                            # encoding is stored as an attribute
                            compressionstyle = d.getAttribute('style')
                            if 'gzip' in compressionstyle:
                                compressionmethod = 'gzip'
                            elif 'bzip2' in compressionstyle:
                                compressionmethod = 'bzip2'
                            elif 'lzma' in compressionstyle:
                                compressionmethod = 'lzma'
                            elif 'xz' in compressionstyle:
                                compressionmethod = 'xz'
                            elif 'application/octet-stream' in compressionstyle:
                                compressionmethod = 'none'
                        elif d.tagName == 'offset':
                            # traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    dataoffset = dd.data.strip()
                        elif d.tagName == 'length':
                            # traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    datalength = dd.data.strip()
                        elif d.tagName == 'size':
                            # traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    datasize = dd.data.strip()
                        elif d.tagName == 'archived-checksum':
                            archivedchecksumtype = d.getAttribute('style')
                            # traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    archivedchecksum = dd.data.strip()
                        elif d.tagName == 'extracted-checksum':
                            extractedchecksumtype = d.getAttribute('style')
                            # traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    extractedchecksum = dd.data.strip()
                # first some sanity checks
                try:
                    dataoffset = int(dataoffset)
                    datalength = int(datalength)
                except ValueError:
                    targetfile.close()
                    os.unlink(targetfile_full)
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'bogus XML values'}
                    return {'status': False, 'error': unpackingerror}

                # more sanity checks
                # the file cannot be outside of the file
                if offset + unpackedsize + dataoffset + datalength > filesize:
                    targetfile.close()
                    os.unlink(targetfile_full)
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data'}
                    return {'status': False, 'error': unpackingerror}

                checkhash = None

                # create a hashing object for the uncompressed file
                if extractedchecksumtype in hashlib.algorithms_available:
                    checkhash = hashlib.new(extractedchecksumtype)

                # seek to the beginning of the file
                checkfile.seek(offset+unpackedsize+dataoffset)
                if compressionmethod == 'none':
                    # if no compression is used just write the bytes
                    # to the target file immediately.
                    bytesread = 0
                    # write in chunks of 10 MB
                    maxbytestoread = 10000000
                    while bytesread != datalength:
                        checkbytes = checkfile.read(min(maxbytestoread, datalength-bytesread))
                        targetfile.write(checkbytes)
                        bytesread += len(checkbytes)
                        if checkhash is not None:
                            checkhash.update(checkbytes)
                else:
                    try:
                        if compressionmethod == 'gzip':
                            decompressor = zlib.decompressobj()
                        elif compressionmethod == 'bzip2':
                            decompressor = bz2.BZ2Decompressor()
                        elif compressionmethod == 'lzma':
                            decompressor = lzma.LZMADecompressor()
                        elif compressionmethod == 'xz':
                            decompressor = lzma.LZMADecompressor()
                        else:
                            targetfile.close()
                            os.unlink(targetfile_full)
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'compression method not supported'}
                            return {'status': False, 'error': unpackingerror}

                        bytesread = 0
                        # read in chunks of 10 MB
                        maxbytestoread = 10000000
                        while bytesread != datalength:
                            checkbytes = checkfile.read(min(maxbytestoread, datalength-bytesread))
                            # decompress the data and write it to
                            # the target file
                            decompressedbytes = decompressor.decompress(checkbytes)
                            targetfile.write(decompressedbytes)
                            targetfile.flush()
                            bytesread += len(checkbytes)
                            if checkhash is not None:
                                checkhash.update(decompressedbytes)

                        # there shouldn't be any unused data
                        if decompressor.unused_data != b'':
                            targetfile.close()
                            os.unlink(targetfile_full)
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'broken data'}
                            return {'status': False, 'error': unpackingerror}

                    except Exception as e:
                        targetfile.close()
                        os.unlink(targetfile_full)
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'broken data'}
                        return {'status': False, 'error': unpackingerror}

                # if there is a checksum compare it to the one that
                # was stored in the file.
                if checkhash is not None:
                    if extractedchecksum != checkhash.hexdigest():
                        targetfile.close()
                        os.unlink(targetfile_full)
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'checksum mismatch'}
                        return {'status': False, 'error': unpackingerror}

                unpackedfilesandlabels.append((targetfile_rel, []))
            else:
                # empty files have no data section associated with it
                unpackedfilesandlabels.append((targetfile_rel, ['empty']))
            targetfile.close()
            maxoffset = max(maxoffset, offset + unpackedsize + dataoffset + datalength)
        # then finally add all of the childnodes
        # which is only happening for subdirectories anyway
        for cn in childfilenodes:
            nodestotraverse.append((cn, os.path.join(nodecwd, nodename)))

    checkfile.close()
    unpackedsize = maxoffset - offset
    if offset == 0 and maxoffset == filesize:
        labels += ['archive', 'xar']
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_xar.signatures = {'xar': b'\x78\x61\x72\x21'}
unpack_xar.minimum_size = 28
