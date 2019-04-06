#!/usr/bin/python3

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
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# Built in carvers/verifiers/unpackers for file systems.
#
# For these unpackers it has been attempted to reduce disk I/O as much
# as possible using the os.sendfile() method, as well as techniques
# described in this blog post:
#
# https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import sys
import os
import shutil
import binascii
import tempfile
import collections
import math
import lzma
import zlib
import stat
import subprocess
import json
import re

encodingstotranslate = ['utf-8', 'ascii', 'latin-1', 'euc_jp', 'euc_jis_2004',
                        'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                        'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                        'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                        'shift_jis_2004', 'shift_jisx0213']


# Unpacking for squashfs
# There are many different flavours of squashfs and configurations
# differ per Linux distribution.
# This is for the "vanilla" squashfs, not for any vendor specific
# versions.
def unpackSquashfs(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack squashfs file system data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    unpackedsize = 0

    if shutil.which('unsquashfs') is None:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'unsquashfs program not found'}
        return {'status': False, 'error': unpackingerror}

    # need at least a header, plus version
    # see /usr/share/magic
    if filesize - offset < 30:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # sanity checks for the squashfs header.
    # First determine the endianness of the file system.
    checkbytes = checkfile.read(4)
    if checkbytes == b'hsqs':
        bigendian = False
        byteorder = 'little'
    else:
        bigendian = True
        byteorder = 'big'

    # then skip to the version, as this is an effective way to filter
    # false positives.
    checkfile.seek(offset+28)
    checkbytes = checkfile.read(2)
    majorversion = int.from_bytes(checkbytes, byteorder=byteorder)

    # So far only squashfs 1-4 have been released (June 2018)
    if majorversion == 0 or majorversion > 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid squashfs version'}
        return {'status': False, 'error': unpackingerror}

    # The location of the size of the squashfs file system depends
    # on the major version of the file. These values can be found in
    # /usr/share/magic or in the squashfs-tools source code
    # ( squashfs_compat.h and squashfs_fs.h )
    if majorversion == 4:
        checkfile.seek(offset+40)
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data to read size'}
            return {'status': False, 'error': unpackingerror}
        squashfssize = int.from_bytes(checkbytes, byteorder=byteorder)
    elif majorversion == 3:
        checkfile.seek(offset+63)
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data to read size'}
            return {'status': False, 'error': unpackingerror}
        squashfssize = int.from_bytes(checkbytes, byteorder=byteorder)
    elif majorversion == 1 or majorversion == 2:
        checkfile.seek(offset+8)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data to read size'}
            return {'status': False, 'error': unpackingerror}
        squashfssize = int.from_bytes(checkbytes, byteorder=byteorder)

    # file size sanity check
    if offset + squashfssize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'file system cannot extend past file'}
        return {'status': False, 'error': unpackingerror}

    # then create a temporary file and copy the data into the
    # temporary file but only if offset != 0
    if offset != 0:
        temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
        # depending on the variant of squashfs a file size can be
        # determined meaning less data needs to be copied.
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, filesize - offset)
        os.fdopen(temporaryfile[0]).close()
    checkfile.close()

    # unpack in a temporary directory, as unsquashfs expects
    # to create the directory itself, but the unpacking directory
    # already exists.
    squashfsunpackdirectory = tempfile.mkdtemp(dir=scanenvironment.temporarydirectory)

    if offset != 0:
        p = subprocess.Popen(['unsquashfs', temporaryfile[1]],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=squashfsunpackdirectory)
    else:
        p = subprocess.Popen(['unsquashfs', filename_full],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=squashfsunpackdirectory)
    (outputmsg, errormsg) = p.communicate()

    if offset != 0:
        os.unlink(temporaryfile[1])

    if p.returncode != 0:
        shutil.rmtree(squashfsunpackdirectory)
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'Not a valid squashfs file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = squashfssize

    # move contents of the unpacked file system
    foundfiles = os.listdir(squashfsunpackdirectory)
    if len(foundfiles) == 1:
        old_dir = os.getcwd()
        if foundfiles[0] == 'squashfs-root':
            os.chdir(os.path.join(squashfsunpackdirectory, 'squashfs-root'))
        else:
            os.chdir(squashfsunpackdirectory)
        listoffiles = os.listdir()
        for l in listoffiles:
            try:
                shutil.move(l, unpackdir_full, copy_function=local_copy2)
            except:
                # TODO: make exception more specific
                # TODO: report
                # not all files can be copied.
                # example: named pipe /dev/initctl in FW_WL_600g_1036A.zip
                pass
        os.chdir(old_dir)

    # clean up the temporary directory
    shutil.rmtree(squashfsunpackdirectory)

    # now add everything that was unpacked
    dirwalk = os.walk(unpackdir_full)
    for direntries in dirwalk:
        # make sure all subdirectories and files can be accessed
        for entryname in direntries[1]:
            fullfilename = os.path.join(direntries[0], entryname)
            if not os.path.islink(fullfilename):
                os.chmod(fullfilename, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            relfilename = scanenvironment.rel_unpack_path(fullfilename)
            unpackedfilesandlabels.append((relfilename, []))
        for entryname in direntries[2]:
            fullfilename = os.path.join(direntries[0], entryname)
            relfilename = scanenvironment.rel_unpack_path(fullfilename)
            unpackedfilesandlabels.append((relfilename, []))

    if offset + unpackedsize != filesize:
        # by default mksquashfs pads to 4K blocks with NUL bytes.
        # The padding is not counted in squashfssize
        checkfile = open(filename_full, 'rb')
        checkfile.seek(offset + unpackedsize)
        padoffset = checkfile.tell()
        if unpackedsize % 4096 != 0:
            paddingbytes = 4096 - unpackedsize % 4096
            checkbytes = checkfile.read(paddingbytes)
            if len(checkbytes) == paddingbytes:
                if checkbytes == paddingbytes * b'\x00':
                    unpackedsize += paddingbytes
                    havepadding = True
        checkfile.close()

    if offset == 0 and unpackedsize == filesize:
        labels.append('squashfs')
        labels.append('filesystem')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# a wrapper around shutil.copy2 to copy symbolic links instead of
# following them and copying the data. This is used in squashfs
# unpacking amongst others.
def local_copy2(src, dest):
    '''Wrapper around shutil.copy2 for squashfs unpacking'''
    return shutil.copy2(src, dest, follow_symlinks=False)


# Derived from public ISO9660 specifications
# https://en.wikipedia.org/wiki/ISO_9660
# http://wiki.osdev.org/ISO_9660
# http://www.ecma-international.org/publications/standards/Ecma-119.htm
#
# Throughout the code there will be references to the corresponding
# sections in various specifications.
#
# The Rock Ridge and SUSP specifications:
#
# https://en.wikipedia.org/wiki/Rock_Ridge
#
# IEEE P1282, Draft Version 1.12
# http://www.ymi.com/ymi/sites/default/files/pdf/Rockridge.pdf
# http://web.archive.org/web/20170404043745/http://www.ymi.com/ymi/sites/default/files/pdf/Rockridge.pdf
#
# IEEE P1281 Draft Version 1.12
# http://www.ymi.com/ymi/sites/default/files/pdf/Systems%20Use%20P1281.pdf
# http://web.archive.org/web/20170404132301/http://www.ymi.com/ymi/sites/default/files/pdf/Systems%20Use%20P1281.pdf
#
# The zisofs specific bits can be found at:
# http://libburnia-project.org/wiki/zisofs
def unpackISO9660(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack an ISO9660 file system.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 32769:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 32769 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0

    # each sector is 2048 bytes long (ECMA 119, 6.1.2). The first 16
    # sectors are reserved for the "system area" (in total 32768 bytes:
    # ECMA 119, 6.2.1)
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+32768)
    unpackedsize += 32768

    # What follows is the data area: ECMA 119, 6.3
    # This consists of a sequence of volume descriptors
    # called volume desciptor set (ECMA 119, 6.7.1)
    # Inside the sequence there should be at least one
    # primary volume descriptor (ECMA 119, 6.7.1.1) and
    # at least one terminator (ECMA 119, 6.7.1.6)
    haveprimary = False
    haveterminator = False
    isbootable = False

    # store whether or not Rock Ridge and zisofs extensions are used
    havesusp = False
    haverockridge = False
    havezisofs = False

    isobuffer = bytearray(2048)

    # read all sectors, until there are none left, or
    # a volume set descriptor terminator is found
    while True:
        bytesread = checkfile.readinto(isobuffer)
        if bytesread != 2048:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough bytes for sector'}
            return {'status': False, 'error': unpackingerror}

        checkbytes = memoryview(isobuffer)

        # each volume descriptor has a type and an identifier
        # (ECMA 119, section 8.1)
        if checkbytes[1:6] != b'CD001':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong identifier'}
            return {'status': False, 'error': unpackingerror}

        volumedescriptoroffset = checkfile.tell()

        # volume descriptor type (ECMA 119, section 8.1.1)
        # 0: boot record
        # 1: primary volume descriptor
        # 2: supplementary volume descriptor or an enhanced volume
        #    descriptor
        # 3: volume partition descriptor
        # 255: volume descriptor set terminator
        if checkbytes[0] == 0:
            # boot record. There is no additional data here, except
            # that there could be a bootloader located here, which
            # could be important for license compliance (isolinux and
            # friends), so mark this as a bootable CD.
            isbootable = True
        elif checkbytes[0] == 1:
            # primary volume descriptor (PVD)
            # ECMA 119, 8.4
            haveprimary = True

            # most fields are stored in both little endian and big
            # endian format and should have the same values.
            if int.from_bytes(checkbytes[80:84], byteorder='little') != int.from_bytes(checkbytes[84:88], byteorder='big'):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'endian mismatch'}
                return {'status': False, 'error': unpackingerror}
            # ECMA 119, 8.4.8
            volume_space_size = int.from_bytes(checkbytes[80:84], byteorder='little')

            # extra sanity check to see if little endian and big endian
            # values match.
            if int.from_bytes(checkbytes[128:130], byteorder='little') != int.from_bytes(checkbytes[130:132], byteorder='big'):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'endian mismatch'}
                return {'status': False, 'error': unpackingerror}

            # ECMA 119, 8.4.12
            logical_size = int.from_bytes(checkbytes[128:130], byteorder='little')

            # sanity check: the ISO image cannot be outside of the file
            if offset + volume_space_size * logical_size > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'image cannot be outside of file'}
                return {'status': False, 'error': unpackingerror}

            # according to https://wiki.osdev.org/ISO_9660 Linux does
            # not use the L-path and M-path but the directory entries
            # instead.
            # The PVD contains the directory root entry (ECMA 119, 8.4.8)
            root_directory_entry = checkbytes[156:190]

            # the entry is formatted as described in ECMA 119, 9.1
            len_dr = root_directory_entry[0]

            # extent location (ECMA 119, 9.1.3)
            extent_location = int.from_bytes(root_directory_entry[2:6], byteorder='little')
            # sanity check: the ISO image cannot be outside of the file
            if offset + extent_location * logical_size > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent location cannot be outside file'}
                return {'status': False, 'error': unpackingerror}

            # sanity check: the ISO image cannot be outside of the
            # declared size of the file
            if extent_location * logical_size > volume_space_size * logical_size:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent location cannot be larger than declared size'}
                return {'status': False, 'error': unpackingerror}

            # extent size (ECMA 119, 9.1.4)
            root_directory_extent_length = int.from_bytes(root_directory_entry[10:14], byteorder='little')
            # sanity check: the ISO image cannot be outside of the file
            if offset + extent_location * logical_size + root_directory_extent_length > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent cannot be outside fle'}
                return {'status': False, 'error': unpackingerror}

            # sanity check: the ISO image cannot be outside of the
            # declared size of the file
            if extent_location * logical_size + root_directory_extent_length > volume_space_size * logical_size:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent cannot be outside of declared size'}
                return {'status': False, 'error': unpackingerror}

            # file flags (ECMA 119, 9.1.6)
            if root_directory_entry[25] >> 1 & 1 != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'file flags for directory wrong'}
                return {'status': False, 'error': unpackingerror}

            # file name length (ECMA 119, 9.1.10)
            file_name_length = root_directory_entry[32]
            extent_filename = root_directory_entry[33:33+file_name_length]

            # ECMA 119, 7.6: file name for root directory is 0x00
            # Some ISO file systems instead said it to 0x01, which
            # according to 6.8.2.2 should not be for the first root
            # entry.
            # Seen in an ISO file included in an ASUS firmware file
            # Modem_FW_4G_AC55U_30043808102_M14.zip
            if extent_filename != b'\x00' and extent_filename != b'\x01':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'root file name wrong'}
                return {'status': False, 'error': unpackingerror}

            # record which extents correspond to which names. This is
            # important for RockRidge relocations.
            extenttoname = {}
            extenttoparent = {}

            # recursively walk all entries/extents in the directory
            # structure.
            # Keep these in a deque data structure for quick access
            # For each extent to unpack add:
            # location of the extent, the size of the extent, location
            # where to unpack, and the name
            extents = collections.deque()
            extents.append((extent_location, root_directory_extent_length, unpackdir, ''))

            # keep track of which extents need to be moved.
            extenttomove = {}
            relocatedextents = set()
            plparent = {}

            firstextentprocessed = False

            # in case rock ridge or zisofs are used the first
            # directory entry in the first extent will contain
            # the SP System Use entry, which specifies how many
            # bytes need to be skipped by default
            # (IEEE P1281, section 5.3)
            suspskip = 0

            # then process all the extents with directory records. The
            # structure is described in ECMA 119, 6.8
            # In the extent pointed to by a directory entry all the
            # entries are concatenated (ECMA 119, 6.8.1).
            while len(extents) != 0:
                (this_extent_location, this_extent_length, this_extent_unpackdir_rel, this_extent_name) = extents.popleft()

                # first seek to the right location in the file
                checkfile.seek(offset + this_extent_location * logical_size)

                # store the starting offset of the current extent
                orig_extent_offset = checkfile.tell()

                # a counter of all data that has been read in this
                # extent so far
                all_extent_offset = 0

                while checkfile.tell() - orig_extent_offset < this_extent_length:
                    # the entry is formatted as described in ECMA 119, 9.1
                    extent_directory_length = ord(checkfile.read(1))

                    # then reset the file pointer
                    checkfile.seek(-1, os.SEEK_CUR)

                    # and store how much data will have been read
                    # after processing this directory.
                    all_extent_offset += extent_directory_length

                    # ECMA 119, 6.8.1.1: "each Directory Record shall
                    # end in the Logical Sector in which it begins"
                    # This means that there could be padding bytes (NUL)
                    if extent_directory_length == 0:
                        # if there is still a logical size block then
                        # jump to the start of that next block
                        all_extent_offset = ((all_extent_offset//logical_size) + 1) * logical_size
                        checkfile.seek(orig_extent_offset + all_extent_offset)
                        continue

                    # read the directory entry and process according
                    # to ECMA 119, 9.1
                    directory_entry = bytearray(extent_directory_length)
                    bytesread = checkfile.readinto(directory_entry)
                    if bytesread != extent_directory_length:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for extent directory'}
                        return {'status': False, 'error': unpackingerror}

                    # extent location (ECMA 119, 9.1.3)
                    extent_location = int.from_bytes(directory_entry[2:6], byteorder='little')
                    # sanity check: the ISO image cannot be outside
                    # of the file
                    if offset + extent_location * logical_size > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent location cannot be outside file'}
                        return {'status': False, 'error': unpackingerror}

                    # sanity check: the ISO image cannot be outside of
                    # the declared size of the file
                    if extent_location * logical_size > volume_space_size * logical_size:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent location cannot be bigger than declared size'}
                        return {'status': False, 'error': unpackingerror}

                    # extent size (ECMA 119, 9.1.4)
                    directory_extent_length = int.from_bytes(directory_entry[10:14], byteorder='little')
                    # sanity check: the ISO image cannot
                    # be outside of the file
                    if offset + extent_location * logical_size + directory_extent_length > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent cannot be outside file'}
                        return {'status': False, 'error': unpackingerror}

                    # sanity check: the ISO image cannot be outside of
                    # the declared size of the file
                    if extent_location * logical_size + directory_extent_length > volume_space_size * logical_size:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent outside of declared size'}
                        return {'status': False, 'error': unpackingerror}

                    # file name length (ECMA 119, 9.1.10)
                    file_name_length = directory_entry[32]

                    # file name (ECMA 119, 9.1.11)
                    extent_filename = directory_entry[33:33+file_name_length].decode()

                    # Grab the system use field (ECMA 119, 9.1.13) as
                    # this is where Rock Ridge and zisofs information
                    # lives (IEEE P1282, section 3).
                    # First check if there is a padding byte
                    # (ECMA 119, 9.1.12)
                    if file_name_length % 2 == 0:
                        # extra check: there should be a padding byte
                        # if the file name length is even
                        # (ECMA 119, 9.1.12)
                        if directory_entry[33+file_name_length] != 0:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'no mandatory padding byte found'}
                            return {'status': False, 'error': unpackingerror}
                        system_use = directory_entry[33+file_name_length+1:]
                    else:
                        system_use = directory_entry[33+file_name_length:]

                    # if RockRidge extensions are used place holder
                    # files are written when a directory has been
                    # moved. These files should not be created, so
                    # indicate whether or not a file needs to be
                    # created or not.
                    createfile = True

                    if len(system_use) != 0:
                        # set the offset to the number of bytes that
                        # should be skipped for each system use area
                        # according to IEEE P1281, section 5.3
                        suoffset = suspskip

                        # add a stub for an alternate name as the
                        # could span multiple entries and need to be
                        # concatenated.
                        alternatename = b''
                        alternatenamecontinue = True
                        renamecurrentdirectory = False
                        renameparentdirectory = False

                        # add a stub for a symbolic name as the could
                        # span multiple entries and need to be
                        # concatenated.
                        symlinktarget = b''
                        symlinkcontinue = True
                        symlinknamecontinue = True

                        # store if PL was already seen
                        # (IEEE P1282, 4.1.5.2)
                        havepl = False

                        # process according to IEEE P1281, section 4
                        while True:
                            if suoffset >= len(system_use) - 2:
                                break

                            signatureword = system_use[suoffset:suoffset+2]
                            sulength = system_use[suoffset+2]
                            if sulength > len(system_use):
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize,
                                                  'fatal': False,
                                                  'reason': 'invalid length in system use field'}
                                return {'status': False, 'error': unpackingerror}
                            suversion = system_use[suoffset+3]
                            sudata = system_use[suoffset+4:suoffset+4+sulength]

                            # the 'SP' entry can only appear once per
                            # directory hierarchy and has to be the
                            # very first entry of the first directory
                            # entry of the first extent
                            # (IEEE P1281, section 5.3)
                            if signatureword == b'SP':
                                if firstextentprocessed:
                                    checkfile.close()
                                    unpackingerror = {'offset': offset+unpackedsize,
                                                      'fatal': False,
                                                      'reason': 'SP used twice in System Use area'}
                                    return {'status': False, 'error': unpackingerror}
                                havesusp = True
                                suspskip = system_use[suoffset+6]
                            else:
                                if not havesusp:
                                    checkfile.close()
                                    unpackingerror = {'offset': offset+unpackedsize,
                                                      'fatal': False,
                                                      'reason': 'SP not first in System Use area'}
                                    return {'status': False, 'error': unpackingerror}
                                # depending on the SUSP word that
                                # follows the contents should be
                                # interpreted differently
                                if signatureword == b'ST':
                                    # terminator (IEEE P1281, 5.4)
                                    break
                                elif signatureword == b'RR':
                                    # this signature word is obsolete
                                    # but still frequently used to
                                    # indicate that RockRidge is used
                                    haverockridge = True
                                elif signatureword == b'CE':
                                    # the continuation area
                                    continuation_block = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                    continuation_offset = int.from_bytes(system_use[suoffset+12:suoffset+16], byteorder='little')
                                    continuation_length = int.from_bytes(system_use[suoffset+20:suoffset+24], byteorder='little')

                                    # first check whether or not the
                                    # continuation data is inside the
                                    # ISO image.
                                    if volume_space_size * logical_size < continuation_block * logical_size + continuation_offset + continuation_length:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'invalid continuation area location or size'}
                                        return {'status': False, 'error': unpackingerror}

                                    # store the current position in the file
                                    oldoffset = checkfile.tell()
                                    checkfile.seek(continuation_block * logical_size + continuation_offset)
                                    # continuation_bytes = checkfile.read(continuation_length)
                                    # TODO

                                    # return to the original position
                                    # in the file
                                    checkfile.seek(oldoffset)
                                elif signatureword == b'NM' and alternatenamecontinue:
                                    # The alternate name field is
                                    # described in IEEE P1282, 4.1.4
                                    nmflags = system_use[suoffset+4]

                                    # sanity check: only one of the
                                    # lower bits can be set
                                    nmflagtotal = (nmflags & 1) + (nmflags >> 1 & 1) + (nmflags >> 2 & 1)
                                    if nmflagtotal > 1:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'invalid flag combination in alternate name field'}
                                        return {'status': False, 'error': unpackingerror}

                                    if sulength - 5 != 0:
                                        alternatename += system_use[suoffset+5:suoffset+sulength]

                                    if nmflags & 1 != 1:
                                        alternatenamecontinue = False
                                    if nmflags >> 1 & 1 == 1:
                                        renamecurrentdirectory = True
                                    if nmflags >> 2 & 1 == 1:
                                        renameparentdirectory = True
                                elif signatureword == b'PD':
                                    # no need to process padding areas
                                    pass
                                elif signatureword == b'PN':
                                    # no need to process POSIX device numbers
                                    pass
                                elif signatureword == b'PX':
                                    # This entry is mandatory, so a
                                    # good indicator that RockRidge is
                                    # used in case there is no RR entry.
                                    haverockridge = True
                                    # don't process POSIX flags
                                    pass
                                elif signatureword == b'SL' and symlinkcontinue:
                                    # symbolic links, IEEE P1282, 4.1.3
                                    symflags = system_use[suoffset+4]

                                    # sanity check: only one of the
                                    # lower bits can be set
                                    nmflagtotal = (symflags & 1) + (symflags >> 1 & 1) + (symflags >> 2 & 1)
                                    if nmflagtotal > 1:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'invalid flag combination in alternate name field'}
                                        return {'status': False, 'error': unpackingerror}

                                    if sulength - 5 != 0:
                                        # the rest of the data is the
                                        # component area the first byte
                                        # is a bit field
                                        if system_use[suoffset+5] & 1 == 1:
                                            symlinknamecontinue = True
                                        else:
                                            symlinknamecontinue = False

                                        if system_use[suoffset+5] & 2 == 2:
                                            if symlinknamecontinue:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize,
                                                                  'fatal': False,
                                                                  'reason': 'invalid flag combination in symbolic name field'}
                                                return {'status': False, 'error': unpackingerror}
                                            symlinktarget = b'.'
                                        elif system_use[suoffset+5] & 4 == 4:
                                            if symlinknamecontinue:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize,
                                                                  'fatal': False,
                                                                  'reason': 'invalid flag combination in symbolic name field'}
                                                return {'status': False, 'error': unpackingerror}
                                            symlinktarget = b'..'
                                        elif system_use[suoffset+5] & 8 == 8:
                                            if symlinknamecontinue:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize,
                                                                  'fatal': False,
                                                                  'reason': 'invalid flag combination in symbolic name field'}
                                                return {'status': False, 'error': unpackingerror}
                                            symlinktarget = b'/'
                                        elif system_use[suoffset+5] & 16 == 16:
                                            pass
                                        elif system_use[suoffset+5] & 32 == 32:
                                            pass
                                        else:
                                            # the next byte is the length
                                            componentlength = system_use[suoffset+6]
                                            if sulength-7 > componentlength:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize,
                                                                  'fatal': False,
                                                                  'reason': 'declared component area size larger than SUSP'}
                                                return {'status': False, 'error': unpackingerror}
                                            symlinktarget += system_use[suoffset+7:suoffset+7+componentlength]

                                    if symflags & 1 != 1:
                                        symlinkcontinue = False
                                elif signatureword == b'SF':
                                    # no need to process sparse file as
                                    # it doesn't seem to be supported
                                    # well in the real world
                                    pass
                                elif signatureword == b'TF':
                                    # don't process time field
                                    pass

                                # the following three signature words
                                # are involved in directory relocations
                                elif signatureword == b'CL':
                                    # IEEE P1282, 4.1.5.1 says:
                                    # If an entry is tagged with CL it
                                    # means that this entry is a
                                    # placeholder file with the same
                                    # name as the directory and that the
                                    # directory should be moved to
                                    # this location.
                                    location_child = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                    if volume_space_size < location_child:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'invalid directory relocation'}
                                        return {'status': False, 'error': unpackingerror}

                                    # don't create, simply store
                                    createfile = False

                                    # store the directory here
                                    extenttomove[location_child] = this_extent_location
                                elif signatureword == b'PL':
                                    # IEEE P1282, 4.1.5.2: PL entry is
                                    # recorded in SUSP field for the
                                    # parent field.
                                    # This value points to the original
                                    # parent of the file.
                                    if extent_filename != '\x01':
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'PL in wrong directory entry'}
                                        return {'status': False, 'error': unpackingerror}

                                    # IEEE P1282, 4.1.5.2: only one
                                    # PL entry is allowed per directory
                                    # entry.
                                    if havepl:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'duplicate PL entry'}
                                        return {'status': False, 'error': unpackingerror}
                                    havepl = True

                                    # location cannot be outside of file
                                    location_parent = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                    if volume_space_size < location_parent:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'relocated directory parent outside of file'}
                                        return {'status': False, 'error': unpackingerror}

                                    # record the original parent for
                                    # this extent
                                    plparent[this_extent_location] = location_parent
                                elif signatureword == b'RE':
                                    # IEEE P1282, 4.1.5.3 describes
                                    # that the directory entry that is
                                    # described is labeled as
                                    # relocated, so record it as such.
                                    relocatedextents.add(extent_location)

                                # zisofs extension
                                elif signatureword == b'ZF':
                                    havezisofs = True
                                    # some sanity checks
                                    pz = system_use[suoffset+4:suoffset+6]
                                    if pz != b'pz':
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'unsupported zisofs compression'}
                                        return {'status': False, 'error': unpackingerror}
                                    zisofs_header_div_4 = system_use[suoffset+6]

                                    # Log2 of Block Size
                                    # must be 15, 16 or 17
                                    zisofs_header_log = system_use[suoffset+7]
                                    if zisofs_header_log not in [15, 16, 17]:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'unsupported zisofs block size log'}
                                        return {'status': False, 'error': unpackingerror}
                                    zisofs_uncompressed = int.from_bytes(system_use[suoffset+8:suoffset+12], byteorder='little')
                            # skip all the other signature words
                            suoffset += sulength

                    # file flags (ECMA 119, 9.1.6)

                    if directory_entry[25] >> 1 & 1 == 1:
                        # directory entry
                        if extent_filename == '\x00':
                            # Look at the file name. If it is '.. then
                            # it is safe to skip, but do a sanity check
                            # to see if the location matches with the
                            # current one.
                            if not this_extent_location == extent_location:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize,
                                                  'fatal': False,
                                                  'reason': 'wrong back reference for . directory'}
                                return {'status': False, 'error': unpackingerror}
                        elif extent_filename == '\x01':
                            # TODO: extra sanity checks to see if parent matches
                            pass
                        else:
                            # store the name of the parent,
                            # for extra sanity checks
                            extenttoparent[extent_location] = this_extent_location

                            extent_unpackdir_rel = os.path.join(this_extent_unpackdir_rel, extent_filename)
                            if haverockridge:
                                if not renamecurrentdirectory or renameoarentdirectory:
                                    if alternatename != b'':
                                        try:
                                            alternatename = alternatename.decode()
                                            extent_unpackdir_rel = os.path.join(this_extent_unpackdir_rel, alternatename)
                                        except UnicodeDecodeError:
                                            pass
                            extenttoname[extent_location] = extent_unpackdir_rel
                            extent_unpackdir_full = scanenvironment.unpack_path(extent_unpackdir_rel)
                            os.mkdir(extent_unpackdir_rel)
                            extents.append((extent_location, directory_extent_length, extent_unpackdir_rel, ''))
                    else:
                        # file entry
                        # store the name of the parent,
                        # for extra sanity checks
                        extenttoparent[extent_location] = this_extent_location
                        outfile_rel = os.path.join(this_extent_unpackdir_rel, extent_filename.rsplit(';', 1)[0])
                        outfile_full = scanenvironment.unpack_path(outfile_rel)
                        if haverockridge:
                            if alternatename != b'':
                                if not renamecurrentdirectory or renameoarentdirectory:
                                    try:
                                        alternatename = alternatename.decode()
                                        outfile_rel = os.path.join(this_extent_unpackdir_rel, alternatename)
                                        outfile_full = scanenvironment.unpack_path(outfile_rel)
                                    except UnicodeDecodeError:
                                        pass

                            if len(symlinktarget) != 0:
                                try:
                                    symlinktarget = symlinktarget.decode()
                                except UnicodeDecodeError:
                                    pass

                                # absolute symlinks can always be created,
                                # as can links to . and ..
                                if os.path.isabs(symlinktarget):
                                    os.symlink(symlinktarget, outfile_full)
                                elif symlinktarget == '.' or symlinktarget == '..':
                                    os.symlink(symlinktarget, outfile_full)
                                else:
                                    # first chdir to the directory, then
                                    # create the link and go back
                                    olddir = os.getcwd()
                                    os.chdir(os.path.dirname(outfile_full))
                                    os.symlink(symlinktarget, outfile_full)
                                    os.chdir(olddir)
                                unpackedfilesandlabels.append((outfile_rel, ['symbolic link']))
                                createfile = False

                        if createfile:
                            outfile = open(outfile_full, 'wb')
                            if not havezisofs:
                                os.sendfile(outfile.fileno(), checkfile.fileno(), offset + extent_location * logical_size, directory_extent_length)
                            else:
                                # first some sanity checks
                                zisofs_oldoffset = checkfile.tell()
                                checkfile.seek(offset + extent_location * logical_size)
                                if filesize - checkfile.tell() < 16:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'not enough bytes for zisofs header'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                # first 8 bytes are the zisofs magic
                                zcheckbytes = checkfile.read(8)
                                if zcheckbytes != b'\x37\xe4\x53\x96\xc9\xdB\xd6\x07':
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'wrong magic for zisofs data'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                # then the uncompressed size. Should be
                                # the same as in the SUSP entry
                                zcheckbytes = checkfile.read(4)
                                if int.from_bytes(zcheckbytes, byteorder='little') != zisofs_uncompressed:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'mismatch for uncompressed size in zisofs header and SUSP'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                # then the zisofs header size
                                zcheckbytes = checkfile.read(1)
                                if not ord(zcheckbytes) == zisofs_header_div_4:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'mismatch between zisofs header and SUSP'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                # then the zisofs log2(block size)
                                zcheckbytes = checkfile.read(1)
                                if not ord(zcheckbytes) == zisofs_header_log:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'mismatch between zisofs header and SUSP'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                block_size = pow(2, zisofs_header_log)

                                # then two reserved bytes
                                zcheckbytes = checkfile.read(2)
                                if not int.from_bytes(zcheckbytes, byteorder='little') == 0:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'wrong value for reserved bytes'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                # then the pointer array
                                blockpointers = math.ceil(zisofs_uncompressed/block_size)+1
                                blockpointerarray = []
                                for b in range(0, blockpointers):
                                    zcheckbytes = checkfile.read(4)
                                    if not len(zcheckbytes) == 4:
                                        unpackingerror = {'offset': checkfile.tell() - offset,
                                                          'fatal': False,
                                                          'reason': 'not enough data for block pointer'}
                                        checkfile.close()
                                        return {'status': False, 'error': unpackingerror}
                                    blockpointer = int.from_bytes(zcheckbytes, byteorder='little')
                                    if blockpointer > directory_extent_length:
                                        unpackingerror = {'offset': checkfile.tell() - offset,
                                                          'fatal': False,
                                                          'reason': 'block pointer cannot be outside extent'}
                                        checkfile.close()
                                        return {'status': False, 'error': unpackingerror}
                                    blockpointerarray.append(blockpointer)

                                totalwritten = 0
                                for b in range(0, len(blockpointerarray) - 1):
                                    blockpointer = blockpointerarray[b]
                                    nextblockpointer = blockpointerarray[b+1]
                                    # in case the two pointers are the
                                    # same a block of NULs should be
                                    # written. Normally this is blocksize
                                    # bytes unless there are fewer bytes
                                    # to be left to write. The
                                    # specification does not mention this.
                                    if blockpointer == nextblockpointer:
                                        if zisofs_uncompressed - totalwritten > block_size:
                                            outfile.seek(block_size, os.SEEK_CUR)
                                            totalwritten += block_size
                                        else:
                                            outfile.seek(zisofs_uncompressed - totalwritten, os.SEEK_CUR)
                                            totalwritten += (zisofs_uncompressed - totalwritten)
                                    else:
                                        totalwritten += outfile.write(zlib.decompress(checkfile.read(nextblockpointer-blockpointer)))

                                # extra sanity check, unsure if this is correct, but seems so
                                if blockpointerarray[-1] < directory_extent_length:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'block pointer ends before directory extent'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                checkfile.seek(zisofs_oldoffset)
                            outfile.close()
                            unpackedfilesandlabels.append((outfile_rel, []))

                    # then skip to the (possible) start of
                    # the next directory entry.
                    checkfile.seek(orig_extent_offset + all_extent_offset)

                firstextentprocessed = True

            for e in extenttomove:
                # First check if all the PL and CL references are
                # correct, before moving extent e to extenttomove[e]
                # 1. extentmove[e] should be the parent
                #    e will be moved to.
                targetparent = extenttomove[e]

                # 2. see if the targetparent is the same
                #    as the recorded value in plparent[e]
                if not targetparent == plparent[e]:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'CL/PL entries do not match'}
                    return {'status': False, 'error': unpackingerror}

                # now move the directory and all its contents
                # to the right location
                shutil.move(extenttoname[e], extenttoname[extenttomove[e]])

                # fix references for unpacked files if necessary
                newunpackedfilesandlabels = []
                for u in unpackedfilesandlabels:
                    if u[0].startswith(extenttoname[e]):
                        newunpackedfilesandlabels.append((u[0].replace(os.path.dirname(extenttoname[e]), extenttoname[extenttomove[e]], 1), u[1]))
                    else:
                        newunpackedfilesandlabels.append(u)
                unpackedfilesandlabels = newunpackedfilesandlabels

                # fix references for extent names
                for n in extenttoname:
                    if n != e:
                        if extenttoname[n].startswith(extenttoname[e]):
                            extenttoname[n] = extenttoname[n].replace(os.path.dirname(extenttoname[e]), extenttoname[extenttomove[e]], 1)

                # finally rewrite the name of the extent moved itself
                extenttoname[e] = extenttoname[e].replace(os.path.dirname(extenttoname[e]), extenttoname[extenttomove[e]], 1)

            # finally return to the old offset to read more
            # volume descriptors
            checkfile.seek(volumedescriptoroffset)
        elif checkbytes[0] == 2:
            # supplementary or enhanced volume descriptor
            # used for for example Joliet (ECMA 119, appendix B.2)
            pass
        elif checkbytes[0] == 3:
            pass
        elif checkbytes[0] == 255:
            # ECMA 119, 8.3.1
            haveterminator = True
            if not haveprimary:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no primary volume descriptor'}
                return {'status': False, 'error': unpackingerror}
        elif checkbytes[0] > 3 and checkbytes[0] < 255:
            # reserved blocks, for future use, have never been
            # implemented for ISO9660.
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'no primary volume descriptor'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2048

        if haveterminator:
            break

    checkfile.close()

    # there should always be at least one terminator. If not,
    # then it is not a valid ISO file
    if not haveterminator:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no volume terminator descriptor'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = volume_space_size * logical_size

    if offset == 0 and unpackedsize == filesize:
        labels += ['iso9660', 'filesystem']
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# JFFS2 https://en.wikipedia.org/wiki/JFFS2
# JFFS2 is a file system that was used on earlier embedded Linux
# system, although it is no longer the first choice for modern systems,
# where for example UBI/UBIFS are chosen.
def unpackJFFS2(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a JFFS2 file system.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 12 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # read the magic of the first inode to see if it is a little endian
    # or big endian file system
    checkbytes = checkfile.read(2)
    if checkbytes == b'\x19\x85':
        bigendian = True
        byteorder = 'big'
    else:
        bigendian = False
        byteorder = 'little'


    dataunpacked = False

    # keep track of which nodes have already been seen. This is to
    # detect if multiple JFFS2 file systems have been concatenated.
    # Also store the version, as inodes could have been reused in the
    # case of hardlinks.
    inodesseenversion = set()
    parentinodesseen = set()

    # the various node types are:
    #
    # * directory entry
    # * inode (containing actual data)
    # * clean marker
    # * padding
    # * summary
    # * xattr
    # * xref
    #
    # For unpacking data only the directory entry and regular inode
    # will be considered.

    DIRENT = 0xe001
    INODE = 0xe002
    CLEANMARKER = 0x2003
    PADDING = 0x2004
    SUMMARY = 0x2006
    XATTR = 0xe008
    XREF = 0xe009

    validinodes = set([DIRENT, INODE, CLEANMARKER,
                       PADDING, SUMMARY, XATTR, XREF])

    inodetoparent = {}

    # keep a list of inodes to file names
    # the root inode (1) always has ''
    inodetofilename = {}
    inodetofilename[1] = ''

    # different kinds of compression
    # Jefferson ( https://github.com/sviehb/jefferson ) defines more
    # types than standard JFFS2. LZMA compression is available as a
    # patch from OpenWrt.
    COMPR_NONE = 0x00
    COMPR_ZERO = 0x01
    COMPR_RTIME = 0x02
    COMPR_RUBINMIPS = 0x03
    COMPR_COPY = 0x04
    COMPR_DYNRUBIN = 0x05
    COMPR_ZLIB = 0x06
    COMPR_LZO = 0x07
    COMPR_LZMA = 0x08

    # LZMA settings from OpenWrt's patch
    lzma_dict_size = 0x2000
    lzma_pb = 0
    lzma_lp = 0
    lzma_lc = 0

    # keep a mapping of inodes to last written position in
    # the file.
    inodetowriteoffset = {}

    # a mapping of inodes to open files
    inodetoopenfiles = {}

    rootseen = False

    # reset the file pointer and read all the inodes
    checkfile.seek(offset)
    while True:
        oldoffset = checkfile.tell()
        if checkfile.tell() == filesize:
            break
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            break

        # first check if the inode magic is valid
        if bigendian:
            if checkbytes not in [b'\x19\x85', b'\x00\x00', b'\xff\xff']:
                break
        else:
            if checkbytes not in [b'\x85\x19', b'\x00\x00', b'\xff\xff']:
                break
        if checkbytes == b'\x00\x00':
            # dirty nodes, skip.
            nodemagictype = 'dirty'
        elif checkbytes == b'\xff\xff':
            # empty space
            unpackedsize += 2
            paddingbytes = 0x10000 - (unpackedsize % 0x10000)
            if paddingbytes != 0:
                checkbytes = checkfile.read(paddingbytes)
                if len(checkbytes) != paddingbytes:
                    break
                unpackedsize += paddingbytes
            continue
        else:
            nodemagictype = 'normal'
        unpackedsize += 2

        # then read the node type
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            break
        inodetype = int.from_bytes(checkbytes, byteorder=byteorder)

        # check if the inode type is actually valid
        if inodetype not in validinodes:
            break

        # then read the size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            break
        inodesize = int.from_bytes(checkbytes, byteorder=byteorder)

        # check if the inode extends past the file
        if checkfile.tell() - 12 + inodesize > filesize:
            break

        # skip dirty nodes
        if nodemagictype == 'dirty':
            checkfile.seek(oldoffset + inodesize)
            unpackedsize = checkfile.tell() - offset
            if unpackedsize % 4 != 0:
                paddingbytes = 4 - (unpackedsize % 4)
                checkfile.seek(paddingbytes, os.SEEK_CUR)
                unpackedsize = checkfile.tell() - offset
            continue

        # then the header CRC of the first 8 bytes in the node
        # The checksum is not the same as the CRC32 algorithm from
        # zlib/binascii, and it is explained here:
        #
        # http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            break
        headercrc = int.from_bytes(checkbytes, byteorder=byteorder)

        # The checksum varies slightly from the one in the zlib/binascii modules
        # as explained here:
        #
        # http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
        #
        # specific implementation for computing checksum grabbed from
        # MIT licensed script found at:
        #
        # https://github.com/sviehb/jefferson/blob/master/src/scripts/jefferson
        checkfile.seek(-12, os.SEEK_CUR)
        checkbytes = checkfile.read(8)

        computedcrc = (binascii.crc32(checkbytes, -1) ^ -1) & 0xffffffff
        if not computedcrc == headercrc:
            break

        # skip past the CRC and start processing the data
        checkfile.seek(4, os.SEEK_CUR)
        unpackedsize = checkfile.tell() - offset

        # process directory entries
        if inodetype == DIRENT:
            # parent inode is first
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            parentinode = int.from_bytes(checkbytes, byteorder=byteorder)

            parentinodesseen.add(parentinode)

            # inode version is next
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            inodeversion = int.from_bytes(checkbytes, byteorder=byteorder)

            # inode number is next
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            inodenumber = int.from_bytes(checkbytes, byteorder=byteorder)

            # skip unlinked inodes
            if inodenumber == 0:
                # first go back to the old offset, then skip
                # the entire inode
                checkfile.seek(oldoffset + inodesize)
                unpackedsize = checkfile.tell() - offset
                if unpackedsize % 4 != 0:
                    paddingbytes = 4 - (unpackedsize % 4)
                    checkfile.seek(paddingbytes, os.SEEK_CUR)
                    unpackedsize = checkfile.tell() - offset
                continue

            # cannot have duplicate inodes
            if (inodenumber, inodeversion) in inodesseenversion:
                break

            inodesseenversion.add((inodenumber, inodeversion))

            # mctime is next, not interesting so no need to process
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break

            # name length is next
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                break
            inodenamelength = ord(checkbytes)
            if inodenamelength == 0:
                break

            # the dirent type is next. Not sure what to do with this
            # value at the moment
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                break

            # skip two unused bytes
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break

            # the node CRC. skip for now
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break

            # the name CRC
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            namecrc = int.from_bytes(checkbytes, byteorder=byteorder)

            # finally the name of the node
            checkbytes = checkfile.read(inodenamelength)
            if len(checkbytes) != inodenamelength:
                break

            try:
                inodename = checkbytes.decode()
            except UnicodeDecodeError:
                break

            # compute the CRC of the name
            computedcrc = (binascii.crc32(checkbytes, -1) ^ -1) & 0xffffffff
            if namecrc != computedcrc:
                break

            # process any possible hard links
            if inodenumber in inodetofilename:
                # the inode number is already known, meaning
                # that this should be a hard link
                os.link(os.path.join(unpackdir_full, inodetofilename[inodenumber]), os.path.join(unpackdir_full, inodename))

                # TODO: determine whether or not to add
                # the hard link to the result set
                # unpackedfilesandlabels.append((os.path.join(unpackdir, inodename),['hardlink']))

            # now add the name to the inode to filename mapping
            if parentinode in inodetofilename:
                inodetofilename[inodenumber] = os.path.join(inodetofilename[parentinode], inodename)

        elif inodetype == INODE:
            # inode number
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            inodenumber = int.from_bytes(checkbytes, byteorder=byteorder)

            # first check if a file name for this inode is known
            if inodenumber not in inodetofilename:
                break

            # skip unlinked inodes
            if inodenumber == 0:
                # first go back to the old offset, then skip
                # the entire inode
                checkfile.seek(oldoffset + inodesize)
                unpackedsize = checkfile.tell() - offset
                if unpackedsize % 4 != 0:
                    paddingbytes = 4 - (unpackedsize % 4)
                    checkfile.seek(paddingbytes, os.SEEK_CUR)
                    unpackedsize = checkfile.tell() - offset
                continue

            # version number, should not be a duplicate
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            inodeversion = int.from_bytes(checkbytes, byteorder=byteorder)

            # file mode
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            filemode = int.from_bytes(checkbytes, byteorder=byteorder)

            if stat.S_ISSOCK(filemode):
                # keep track of whatever is in the file and report
                pass
            elif stat.S_ISDIR(filemode):
                # create directories, but skip them otherwise
                os.makedirs(os.path.join(unpackdir_full, inodetofilename[inodenumber]), exist_ok=True)
                checkfile.seek(oldoffset + inodesize)
                continue
            elif stat.S_ISLNK(filemode):
                # skip ahead 24 bytes to the size of the data
                checkfile.seek(24, os.SEEK_CUR)

                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                linknamelength = int.from_bytes(checkbytes, byteorder=byteorder)

                # skip ahead 16 bytes to the data containing the link name
                checkfile.seek(16, os.SEEK_CUR)
                checkbytes = checkfile.read(linknamelength)
                if len(checkbytes) != linknamelength:
                    break
                try:
                    fn_rel = os.path.join(unpackdir, inodetofilename[inodenumber])
                    fn_full = scanenvironment.unpack_path(fn_rel)
                    os.symlink(checkbytes.decode(), fn_full)
                    unpackedfilesandlabels.append((fn_full, ['symbolic link']))
                    dataunpacked = True
                except UnicodeDecodeError:
                    break
            elif stat.S_ISREG(filemode):
                # skip ahead 20 bytes to the offset of where to write data
                checkfile.seek(20, os.SEEK_CUR)

                # the write offset is useful as a sanity check: either
                # it is 0, or it is the previous offset, plus the
                # previous uncompressed length.
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                writeoffset = int.from_bytes(checkbytes, byteorder=byteorder)

                if writeoffset == 0:
                    if inodenumber in inodetowriteoffset:
                        break
                    if inodenumber in inodetoopenfiles:
                        break
                    # open a file and store it as a reference
                    fn_rel = os.path.join(unpackdir, inodetofilename[inodenumber])
                    fn_full = scanenvironment.unpack_path(fn_rel)
                    outfile = open(fn_full, 'wb')
                    inodetoopenfiles[inodenumber] = outfile
                else:
                    if writeoffset != inodetowriteoffset[inodenumber]:
                        break
                    if inodenumber not in inodetoopenfiles:
                        break
                    outfile = inodetoopenfiles[inodenumber]

                # the offset to the compressed data length
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                compressedsize = int.from_bytes(checkbytes, byteorder=byteorder)

                # read the decompressed size
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                decompressedsize = int.from_bytes(checkbytes, byteorder=byteorder)

                # find out which compression algorithm has been used
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                    break
                compression_used = ord(checkbytes)

                # skip ahead 11 bytes to the actual data
                checkfile.seek(11, os.SEEK_CUR)
                checkbytes = checkfile.read(compressedsize)
                if len(checkbytes) != compressedsize:
                    break

                # Check the compression that's used as it could be that
                # for a file compressed and uncompressed nodes are mixed
                # in case the node cannot be compressed efficiently
                # and the compressed data would be larger than the
                # original data.
                if compression_used == COMPR_NONE:
                    # the data is not compressed, so can be written
                    # to the output file immediately
                    outfile.write(checkbytes)
                    dataunpacked = True
                elif compression_used == COMPR_ZLIB:
                    # the data is zlib compressed, so first decompress
                    # before writing
                    try:
                        outfile.write(zlib.decompress(checkbytes))
                        dataunpacked = True
                    except Exception as e:
                        break
                elif compression_used == COMPR_LZMA:
                    # The data is LZMA compressed, so create a
                    # LZMA decompressor with custom filter, as the data
                    # is stored without LZMA headers.
                    jffs_filters = [{'id': lzma.FILTER_LZMA1,
                                     'dict_size': lzma_dict_size,
                                     'lc': lzma_lc, 'lp': lzma_lp,
                                     'pb': lzma_pb}]

                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=jffs_filters)

                    try:
                        outfile.write(decompressor.decompress(checkbytes))
                        dataunpacked = True
                    except Exception as e:
                        break
                #elif compression_used == COMPR_LZO:
                # The JFFS2 version of LZO somehow cannot be unpacked with
                # python-lzo
                else:
                    break
                inodetowriteoffset[inodenumber] = writeoffset + decompressedsize
            else:
                # unsure what to do here now
                pass

        checkfile.seek(oldoffset + inodesize)
        unpackedsize = checkfile.tell() - offset
        if unpackedsize % 4 != 0:
            paddingbytes = 4 - (unpackedsize % 4)
            checkfile.seek(paddingbytes, os.SEEK_CUR)
            unpackedsize = checkfile.tell() - offset

    checkfile.close()

    if not dataunpacked:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no data unpacked'}
        return {'status': False, 'error': unpackingerror}

    # close all the open files
    for i in inodetoopenfiles:
        inodetoopenfiles[i].flush()
        inodetoopenfiles[i].close()
        fn_rel = scanenvironment.rel_unpack_path(inodetoopenfiles[i].name)
        unpackedfilesandlabels.append((fn_rel, []))

    # check if a valid root node was found.
    if 1 not in parentinodesseen:
        for i in inodetoopenfiles:
            os.unlink(inodetoopenfiles[i])
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no valid root file node'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and filesize == unpackedsize:
        labels.append('jffs2')
        labels.append('filesystem')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# Unpacker for the ext2, ext3, ext4 file systems
# The file system is documented at:
#
# http://www.nongnu.org/ext2-doc/ext2.html
#
# The format is described in Chapter 3 and is used to implement
# several sanity checks. References to the specification point
# to this document. The heavy lifting is done using e2tools
# because it already takes care of deleted files, etc. through
# e2fsprogs-libs.
def unpackExt2(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack an ext2/ext3/ext4 file system.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # superblock starts at offset 1024 and is 1024 bytes (section 3.1)
    if filesize - offset < 2048:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for superblock'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('e2ls') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'e2ls program not found'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('e2cp') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'e2cp program not found'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip directly to the superblock
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+1024)
    unpackedsize += 1024

    # Process the superblock and run many sanity checks.
    # Extract the total number of inodes in the file system
    # (section 3.1.1)
    checkbytes = checkfile.read(4)
    totalinodecount = int.from_bytes(checkbytes, byteorder='little')
    if totalinodecount == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'inodes cannot be 0'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the total number of blocks in the file system (section 3.1.2)
    checkbytes = checkfile.read(4)
    totalblockcount = int.from_bytes(checkbytes, byteorder='little')
    if totalblockcount == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'block count cannot be 0'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # reserved block count for the superuser (section 3.1.3)
    checkbytes = checkfile.read(4)
    reservedblockcount = int.from_bytes(checkbytes, byteorder='little')
    if reservedblockcount > totalblockcount:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved blocks cannot exceed total blocks'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # free blocks in the system (section 3.1.4)
    checkbytes = checkfile.read(4)
    freeblockcount = int.from_bytes(checkbytes, byteorder='little')
    if freeblockcount > totalblockcount:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'free blocks cannot exceed total blocks'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # free inodes in the system (section 3.1.5)
    checkbytes = checkfile.read(4)
    freeinodes = int.from_bytes(checkbytes, byteorder='little')
    if freeinodes > totalinodecount:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'free inodes cannot exceed total inodes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # location of the first data block. Has to be 0 or 1. (section 3.1.6)
    checkbytes = checkfile.read(4)
    firstdatablock = int.from_bytes(checkbytes, byteorder='little')
    if firstdatablock != 0 and firstdatablock != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for first data block'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the block size (section 3.1.7)
    checkbytes = checkfile.read(4)
    blocksize = 1024 << int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # check if the declared size is bigger than the file's size
    if offset + (totalblockcount * blocksize) > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'declared file system size larger than file size'}
        return {'status': False, 'error': unpackingerror}

    # skip 4 bytes
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # determine the blocks per group (section 3.1.9)
    checkbytes = checkfile.read(4)
    blocks_per_group = int.from_bytes(checkbytes, byteorder='little')
    if blocks_per_group == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for blocks per group'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4
    blockgroups = math.ceil(totalblockcount/blocks_per_group)

    # then skip a bunch of not so interesting values
    checkfile.seek(offset + 1024 + 76)
    unpackedsize = 1024+76

    # check the revision level (section 3.1.23)
    checkbytes = checkfile.read(4)
    revision = int.from_bytes(checkbytes, byteorder='little')
    if not (revision == 0 or revision == 1):
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid ext2/3/4 revision'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # skip 8 bytes
    checkfile.seek(8, os.SEEK_CUR)
    unpackedsize += 8

    # read the inode size, cannot be larger than
    # block size (section 3.1.27)
    checkbytes = checkfile.read(2)
    inodesize = int.from_bytes(checkbytes, byteorder='little')
    if inodesize > blocksize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'inode size cannot be larger than block size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # skip 10 bytes
    checkfile.seek(10, os.SEEK_CUR)
    unpackedsize += 10

    # read the RO compat flags (section 3.1.31)
    checkbytes = checkfile.read(4)
    rocompatflags = int.from_bytes(checkbytes, byteorder='little')
    if rocompatflags & 1 == 1:
        sparsesuperblocks = True
    else:
        sparsesuperblocks = False

    # store the current offset
    oldoffset = checkfile.tell()

    if revision != 0:
        # Now check for each block group if there is a copy of the
        # superblock except if the sparse super block features is set
        # (section 2.5).
        # Find the right offset and then check if the magic byte is at
        # that location, unless the block size is 1024, then it will be at
        # the location + 1024.
        for i in range(1, blockgroups):
            # super blocks are always present in block group 0 and 1, except
            # if the block size = 1024
            # Block group 0 contains the original superblock, which has
            # already been processed.
            if not sparsesuperblocks:
                if blocksize == 1024:
                    blockoffset = offset + i*blocksize*blocks_per_group+1024
                else:
                    blockoffset = offset + i*blocksize*blocks_per_group
            else:
                # if the sparse superblock feature is enabled
                # the superblock can be found in each superblock
                # that is a power of 3, 5 or 7
                sparsefound = False
                for p in [3, 5, 7]:
                    if pow(p, int(math.log(i, p))) == i:
                        if blocksize == 1024:
                            blockoffset = offset + i*blocksize*blocks_per_group+1024
                        else:
                            blockoffset = offset + i*blocksize*blocks_per_group
                        sparsefound = True
                        break
                if not sparsefound:
                    # for anything that is not a power of 3, 5 or 7
                    continue

            # jump to the location of the magic header (section 3.1.16)
            # and check its value. In a valid super block this value should
            # always be the same.
            checkfile.seek(blockoffset + 0x38)
            checkbytes = checkfile.read(2)
            if not checkbytes == b'\x53\xef':
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid super block copy'}
                return {'status': False, 'error': unpackingerror}

    unpackedsize = totalblockcount * blocksize

    # return to the old offset
    checkfile.seek(oldoffset)

    # read the volume id
    checkbytes = checkfile.read(16)
    volumeid = binascii.hexlify(checkbytes).decode()

    # read the volume name
    checkbytes = checkfile.read(16)
    volumename = ''
    try:
        volumename = checkbytes.split(b'\x00')[0].decode()
    except UnicodeDecodeError:
        pass

    # 'last mounted' path, likely empty
    checkbytes = checkfile.read(64)
    lastmountedpath = ''
    try:
        lastmountedpath = checkbytes.split(b'\x00')[0].decode()
    except UnicodeDecodeError:
        pass

    # e2tools can work with trailing data, but if there is any data
    # preceding the file system then some carving has to be done first.
    havetmpfile = False
    if not offset == 0:
        # if files are larger than a certain limit, then os.sendfile()
        # won't write more data than 2147479552 so write bytes
        # out in chunks. Reference:
        # https://bugzilla.redhat.com/show_bug.cgi?id=612839
        temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
        if unpackedsize > 2147479552:
            bytesleft = unpackedsize
            bytestowrite = min(bytesleft, 2147479552)
            readoffset = offset
            while bytesleft > 0:
                os.sendfile(temporaryfile[0], checkfile.fileno(), readoffset, bytestowrite)
                bytesleft -= bytestowrite
                readoffset += bytestowrite
                bytestowrite = min(bytesleft, 2147479552)
        else:
            os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True
    checkfile.close()

    # Now read the contents of the file system with e2ls and
    # copy the files with e2cp.
    # Unfortunately e2cp does not allow recursive copying, so the entire
    # directory structure has to be walked recursively and recreated.
    # Individual files have then to be copied with e2cp.
    ext2dirstoscan = collections.deque([''])

    # store a mapping for inodes and files. This is needed to detect
    # hard links, where files have the same inode.
    inodetofile = {}
    filetoinode = {}

    # keep track of if any data was unpacked. Since file systems that
    # have been created always have the "lost+found" directory it means
    # that if no data could be unpacked it was not a valid file system,
    # or at least it was not a useful file system.
    dataunpacked = False

    while True:
        try:
            ext2dir = ext2dirstoscan.popleft()
        except IndexError:
            # there are no more entries to process
            break
        if havetmpfile:
            p = subprocess.Popen(['e2ls', '-lai', temporaryfile[1] + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['e2ls', '-lai', str(filename_full) + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            if havetmpfile:
                os.unlink(temporaryfile[1])
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'e2ls error'}
            return {'status': False, 'error': unpackingerror}
        dirlisting = outputmsg.rstrip().split(b'\n')
        for d in dirlisting:
            # ignore deleted files
            if d.strip().startswith(b'>'):
                continue
            dirsplit = re.split(b'\s+', d.strip(), 7)
            if len(dirsplit) != 8:
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data in directory entry'}
                return {'status': False, 'error': unpackingerror}
            (inode, filemode, userid, groupid, size, filedate, filetime, ext2name) = re.split(b'\s+', d.strip(), 7)
            filemode = int(filemode, base=8)

            dataunpacked = True

            # try to make sense of the filename by decoding it first.
            # This might fail.
            namedecoded = False
            for c in encodingstotranslate:
                try:
                    ext2name = ext2name.decode(c)
                    namedecoded = True
                    break
                except Exception as e:
                    pass
            if not namedecoded:
                if havetmpfile:
                    os.unlink(temporaryfile[1])
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'could not decode file name'}
                return {'status': False, 'error': unpackingerror}

            # Check the different file types
            if stat.S_ISDIR(filemode):
                # It is a directory, so create it and then add
                # it to the scanning queue, unless it is . or ..
                if ext2name == '.' or ext2name == '..':
                    continue
                newext2dir = os.path.join(ext2dir, ext2name)
                ext2dirstoscan.append(newext2dir)
                ext2dir_rel = os.path.join(unpackdir, newext2dir)
                ext2dir_full = scanenvironment.unpack_path(ext2dir_rel)
                os.mkdir(ext2dir_full)
                unpackedfilesandlabels.append((ext2dir_rel, []))
            elif stat.S_ISBLK(filemode):
                # ignore block devices
                continue
            elif stat.S_ISCHR(filemode):
                # ignore character devices
                continue
            elif stat.S_ISFIFO(filemode):
                # ignore FIFO
                continue
            elif stat.S_ISSOCK(filemode):
                # ignore sockets
                continue

            fullext2name = os.path.join(ext2dir, ext2name)
            filetoinode[fullext2name] = inode
            if stat.S_ISLNK(filemode):
                # e2cp cannot copy symbolic links
                # so just record it as a symbolic link
                # TODO: process symbolic links
                pass
            elif stat.S_ISREG(filemode):
                fileunpacked = False
                if inode not in inodetofile:
                    inodetofile[inode] = fullext2name
                    # use e2cp to copy the file
                    ext2dir_rel = os.path.join(unpackdir, ext2dir)
                    ext2dir_full = scanenvironment.unpack_path(ext2dir_rel)
                    if havetmpfile:
                        p = subprocess.Popen(['e2cp', temporaryfile[1] + ":" + fullext2name, "-d", ext2dir_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    else:
                        p = subprocess.Popen(['e2cp', str(filename_full) + ":" + fullext2name, "-d", ext2dir_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (outputmsg, errormsg) = p.communicate()
                    if p.returncode != 0:
                        if havetmpfile:
                            os.unlink(temporaryfile[1])
                        unpackingerror = {'offset': offset, 'fatal': False,
                                          'reason': 'e2cp error'}
                        return {'status': False, 'error': unpackingerror}
                    fileunpacked = True
                else:
                    # hardlink the file to an existing
                    # file and record it as such.
                    if inodetofile[inode] != fullext2name:
                        os.link(os.path.join(unpackdir_full, inodetofile[inode]), os.path.join(unpackdir_full, fullext2name))
                        fileunpacked = True
                if fileunpacked:
                    unpackedfilesandlabels.append((os.path.join(unpackdir, fullext2name), []))

    # cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])

    # only report if any data was unpacked
    if not dataunpacked:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no data unpacked'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and filesize == unpackedsize:
        labels.append('ext2')
        labels.append('filesystem')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# VMware VMDK files
#
# The website:
#
# https://www.vmware.com/app/vmdk/?src=vmdk
#
# has a PDF of specification, but these are a bit outdated
#
# Newer specs:
#
# https://www.vmware.com/support/developer/vddk/vmdk_50_technote.pdf
#
# https://github.com/libyal/libvmdk/blob/master/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc
# in section 4
#
# For now just focus on files where the entire file is VMDK
def unpackVMDK(fileresult, scanenvironment, offset, unpackdir):
    '''Convert a VMware VMDK file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    if filesize - offset < 512:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 512 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('qemu-img') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'qemu-img program not found'}
        return {'status': False, 'error': unpackingerror}

    # first run qemu-img in case the whole file is the VMDK file
    if offset == 0:
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', filename_full],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            # extra sanity check to see if it is valid JSON
            try:
                vmdkjson = json.loads(standardout)
            except:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'no valid JSON output from qemu-img'}
                return {'status': False, 'error': unpackingerror}
            if filename_full.suffix.lower() == '.vmdk':
                outputfile_rel = os.path.join(unpackdir, filename_full.stem)
            else:
                outputfile_rel = os.path.join(unpackdir, 'unpacked-from-vmdk')

            outputfile_full = scanenvironment.unpack_path(outputfile_rel)
            # now convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', filename_full, outputfile_full],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                if os.path.exists(outputfile_full):
                    os.unlink(outputfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert file'}
                return {'status': False, 'error': unpackingerror}

            labels.append('vmdk')
            labels.append('filesystem')
            unpackedfilesandlabels.append((outputfile_rel, []))
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'Not a valid VMDK file or cannot unpack'}
    return {'status': False, 'error': unpackingerror}


# QEMU qcow2 files
#
# Specification can be found in docs/interop in the QEMU repository
#
# https://git.qemu.org/?p=qemu.git;a=blob;f=docs/interop/qcow2.txt;hb=HEAD
def unpackQcow2(fileresult, scanenvironment, offset, unpackdir):
    '''Convert a QEMU qcow2 file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}

    if filesize - offset < 72:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 72 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('qemu-img') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'qemu-img program not found'}
        return {'status': False, 'error': unpackingerror}

    # first run qemu-img in case the whole file is the qcow2 file
    if offset == 0:
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', filename_full],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            # extra sanity check to see if it is valid JSON
            try:
                vmdkjson = json.loads(standardout)
            except:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'no valid JSON output from qemu-img'}
                return {'status': False, 'error': unpackingerror}
            if filename_full.suffix.lower() == '.qcow2':
                outputfile_rel = os.path.join(unpackdir, filename_full.stem)
            else:
                outputfile_rel = os.path.join(unpackdir, 'unpacked-from-qcow2')

            outputfile_full = scanenvironment.unpack_path(outputfile_rel)
            # now convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', filename_full, outputfile_full],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                if os.path.exists(outputfile_full):
                    os.unlink(outputfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert file'}
                return {'status': False, 'error': unpackingerror}

            labels.append('qemu')
            labels.append('qcow2')
            labels.append('filesystem')
            unpackedfilesandlabels.append((outputfile_rel, []))
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'Not a valid qcow2 file or cannot unpack'}
    return {'status': False, 'error': unpackingerror}


# VirtualBox VDI
#
# https://forums.virtualbox.org/viewtopic.php?t=8046
def unpackVDI(fileresult, scanenvironment, offset, unpackdir):
    '''Convert a VirtualBox VDI file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}

    if filesize - offset < 512:
        unpackingerror = {'offset': offset,
                          'fatal': False,
                          'reason': 'File too small (less than 512 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('qemu-img') is None:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'qemu-img program not found'}
        return {'status': False, 'error': unpackingerror}

    # open the file skip over the magic header bytes
    checkfile = open(filename_full, 'rb')

    # This assumes the Oracle flavour of VDI. There have been
    # others in the past.
    checkfile.seek(offset+40)
    unpackedsize = 40

    # 24 NUL bytes
    checkbytes = checkfile.read(24)
    if checkbytes != b'\x00' * 24:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for padding bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 24

    # then the image signature
    checkbytes = checkfile.read(4)
    if checkbytes != b'\x7f\x10\xda\xbe':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for image signature'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # major version
    checkbytes = checkfile.read(2)
    majorversion = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # minor version
    checkbytes = checkfile.read(2)
    minorversion = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # size of header, should be 0x190
    checkbytes = checkfile.read(4)
    headersize = int.from_bytes(checkbytes, byteorder='little')
    if headersize != 0x190:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for header size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # image type
    checkbytes = checkfile.read(4)
    imagetype = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # image flags
    checkbytes = checkfile.read(4)
    imageflags = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # image description, unclear how big it is
    #checkbytes = checkfile.read(32)
    #unpackedsize += 32

    # skip to 0x154
    checkfile.seek(offset + 0x154)
    unpackedsize = 0x154

    # offset blocks
    checkbytes = checkfile.read(4)
    offsetblocks = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # offset data
    checkbytes = checkfile.read(4)
    offsetdata = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # cylinders
    checkbytes = checkfile.read(4)
    cylinders = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # heads
    checkbytes = checkfile.read(4)
    heads = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # sectors
    checkbytes = checkfile.read(4)
    sectors = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # sector size (should be 512)
    checkbytes = checkfile.read(4)
    sectorsize = int.from_bytes(checkbytes, byteorder='little')
    if sectorsize != 512:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for sector size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # skip unused bytes
    checkfile.seek(4, os.SEEK_CUR)

    # disk size (uncompressed)
    checkbytes = checkfile.read(8)
    disksize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    # block size
    checkbytes = checkfile.read(4)
    blocksize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # block extra data
    checkbytes = checkfile.read(4)
    blockextradata = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # blocks in hdd
    checkbytes = checkfile.read(4)
    blocksinhdd = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # blocks allocated
    checkbytes = checkfile.read(4)
    blocksallocated = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # now there is enough information to do some sanity checks
    # First see if the file is large enough
    if offset + (2+blocksallocated) * blocksize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'data cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}

    # check to see if the VDI is the entire file. If so unpack it.
    if offset == 0 and (2+blocksallocated) * blocksize == filesize:
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', filename_full],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            # extra sanity check to see if it is valid JSON
            try:
                vmdkjson = json.loads(standardout)
            except:
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no valid JSON output from qemu-img'}
                return {'status': False, 'error': unpackingerror}
            if filename_full.suffix.lower() == '.vdi':
                outputfile_rel = os.path.join(unpackdir, filename_full.stem)
            else:
                outputfile_rel = os.path.join(unpackdir, 'unpacked-from-vdi')

            outputfile_full = scanenvironment.unpack_path(outputfile_rel)
            # now convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', filename_full, outputfile_full],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                if os.path.exists(outputfile_full):
                    os.unlink(outputfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert file'}
                return {'status': False, 'error': unpackingerror}

            labels.append('virtualbox')
            labels.append('vdi')
            labels.append('filesystem')
            unpackedfilesandlabels.append((outputfile_rel, []))
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    # TODO: snapshots and carving

    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'Not a valid VDI file or cannot unpack'}
    return {'status': False, 'error': unpackingerror}


# D-Link ROMFS. This code is inspired by the unpacking code
# from binwalk:
#
# https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk/plugins/dlromfsextract.py
#
# which was released under the MIT license. The license can be found in the file
# README.md in the root of this project.
def unpackDlinkRomfs(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a D-Link ROMFS'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # open the file
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # check the endianness, don't support anything but little endian
    checkbytes = checkfile.read(4)
    if checkbytes != b'\x2emoR':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported endianness'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize += 4

    # skip 4 bytes
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # skip 4 bytes (file system size?, leave here for future reference)
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # skip the superblock
    checkfile.seek(offset + 32)
    unpackedsize = 32

    endentry = sys.maxsize

    entryuidtopath = {}

    maxunpacked = unpackedsize

    while True:
        # read metadata entries, but stop as soon
        # as the data part starts.
        if checkfile.tell() >= offset + endentry:
            break

        if checkfile.tell() + 20 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for entry'}
            return {'status': False, 'error': unpackingerror}

        # read the type
        checkbytes = checkfile.read(4)
        entrytype = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        isdir = False
        if entrytype & 0x00000001 == 0x00000001:
            isdir = True

        isdata = False
        if entrytype & 0x00000008 == 0x00000008:
            isdata = True

        iscompressed = False
        if entrytype & 0x005B0000 == 0x005B0000:
            iscompressed = True

        # skip over a few fields
        checkfile.seek(8, os.SEEK_CUR)
        unpackedsize += 8

        # read the size
        checkbytes = checkfile.read(4)
        entrysize = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        # skip 4 bytes
        checkfile.seek(4, os.SEEK_CUR)
        unpackedsize += 4

        # read the offset
        checkbytes = checkfile.read(4)
        entryoffset = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        # entry cannot be outside of the file
        if offset + entryoffset + entrysize > filesize:
            break

        # offset cannot be smaller than previous offset
        if endentry != sys.maxsize:
            if entryoffset < endentry:
                break
        else:
            endentry = entryoffset

        # skip over a few bytes
        checkfile.seek(4, os.SEEK_CUR)
        unpackedsize += 4

        # uid
        checkbytes = checkfile.read(4)
        try:
            entryuid = int(checkbytes.decode())
        except UnicodeDecodeError:
            break
        unpackedsize += 4

        if entryuid in entryuidtopath:
            curdir = entryuidtopath[entryuid]
        else:
            curdir = ''

        # store the current offset
        oldoffset = checkfile.tell()
        checkfile.seek(offset + entryoffset)

        # read directory entries
        if isdir:
            if entryuid in entryuidtopath:
                outfile_rel = os.path.join(unpackdir, entryuidtopath[entryuid])
                outfile_full = scanenvironment.unpack_path(outfile_rel)
                os.mkdir(outfile_full)
                unpackedfilesandlabels.append((outfile_rel, []))
            entrybytesread = 0
            while entrybytesread < entrysize:
                # directory uid
                checkbytes = checkfile.read(4)
                diruid = int.from_bytes(checkbytes, byteorder='little')
                entrybytesread += 4

                # skip 4 bytes
                checkfile.seek(4, os.SEEK_CUR)
                entrybytesread += 4

                # directory name entry
                dirname = b''
                while True:
                    checkbytes = checkfile.read(1)
                    entrybytesread += 1
                    if checkbytes == b'\x00':
                        break
                    if entrybytesread > entrysize:
                        break
                    dirname += checkbytes

                # store the name of the entry so far:
                # uid, 4 bytes skipped and NUL-terminated name
                total_size = 4 + 4 + len(dirname)+1

                try:
                    dirname = dirname.decode()
                except UnicodeDecodeError:
                    pass

                # no need to create/store current directory
                # and the parent directory
                if dirname not in ['.', '..']:
                    entryuidtopath[diruid] = os.path.join(curdir, dirname)

                # entries are aligned on 32 byte boundaries
                count = total_size % 32

                if count != 0:
                    checkfile.seek(32 - count, os.SEEK_CUR)
                    entrybytesread += (32 - count)
            maxunpacked = max(maxunpacked, offset + entryoffset + entrysize)
        elif isdata:
            if entryuid in entryuidtopath:
                outfile_rel = os.path.join(unpackdir, entryuidtopath[entryuid])
                outfile_full = scanenvironment.unpack_path(outfile_rel)
                outfile = open(outfile_full, 'wb')
                if iscompressed:
                    # try to decompress using LZMA. If this is not successful
                    # simply copy the data. It happens that some data has the
                    # compression flag set, but is included without being
                    # compressed.
                    try:
                        outfile.write(lzma.decompress(checkfile.read(entrysize)))
                    except:
                        os.sendfile(outfile.fileno(), checkfile.fileno(), offset + entryoffset, entrysize)
                else:
                    os.sendfile(outfile.fileno(), checkfile.fileno(), offset + entryoffset, entrysize)
                outfile.close()
                unpackedfilesandlabels.append((outfile_rel, []))
                maxunpacked = max(maxunpacked, offset + entryoffset + entrysize)

        # return to the old offset
        checkfile.seek(oldoffset)

    unpackedsize = maxunpacked

    if offset == 0 and unpackedsize == filesize:
        labels.append('filesystem')
        labels.append('d-link')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# FAT file system
# https://en.wikipedia.org/wiki/File_Allocation_Table
# https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
def unpackFAT(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack FAT file systems'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # open the file
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # jump instruction
    checkbytes = checkfile.read(3)
    if checkbytes[0] != 0xeb and checkbytes[2] != 0x90:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid jump instruction'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 3

    # OEM name
    checkbytes = checkfile.read(8)
    try:
        oemname = checkbytes.decode()
    except UnicodeDecodeError:
        pass
    unpackedsize += 8

    # what follows now is depending on the version of the
    # operating system that was used. All first use a
    # DOS 2.0 BIOS parameter block.

    # bytes per logical sector, power of two, minimum of 32
    checkbytes = checkfile.read(2)
    bytespersector = int.from_bytes(checkbytes, byteorder='little')
    if bytespersector < 32:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid bytes per sector'}
        return {'status': False, 'error': unpackingerror}
    # TODO: use << and >> for this
    if pow(2, int(math.log(bytespersector, 2))) != bytespersector:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid bytes per sector'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # logical sectors per cluster
    checkbytes = checkfile.read(1)
    sectorspercluster = ord(checkbytes)
    if sectorspercluster not in [1, 2, 4, 8, 16, 32, 64, 128]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid sectors per cluster'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # reserved logical sectors
    checkbytes = checkfile.read(2)
    reservedlogicalsectors = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # number of allocation tables
    checkbytes = checkfile.read(1)
    numberoffat = ord(checkbytes)
    unpackedsize += 1

    # maximum number of root directory entries
    checkbytes = checkfile.read(2)
    maxrootentries = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # total logical sectors
    # "if zero, use 4 byte value at offset 0x020"
    checkbytes = checkfile.read(2)
    totallogicalsectors = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # media descriptor
    checkbytes = checkfile.read(1)
    mediadescriptor = ord(checkbytes)
    unpackedsize += 1

    # logical sectors per FAT
    # "FAT32 sets this to 0 and uses the 32-bit value at offset 0x024 instead."
    checkbytes = checkfile.read(2)
    logicalperfat = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # then things start to diverge. Assume for now that
    # the DOS 3.31 boot partition block follows now

    # physical sectors, skip
    checkfile.seek(2, os.SEEK_CUR)
    unpackedsize += 2

    # number of heads, skip
    checkfile.seek(2, os.SEEK_CUR)
    unpackedsize += 2

    # hidden sectors
    checkbytes = checkfile.read(4)
    hiddensectors = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # total logical sectors
    if totallogicalsectors == 0:
        checkbytes = checkfile.read(4)
        totallogicalsectors = int.from_bytes(checkbytes, byteorder='little')
    else:
        checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # first read a few bytes to see if this is a FAT32 extended bios
    # parameter block or an extended bios parameter block
    fattype = ''
    isfat32 = False
    checkbytes = checkfile.read(4)
    if checkbytes[2] == 0x28 or checkbytes[2] == 0x29:
        # extended bios parameter block,
        extended = False
        if checkbytes[2] == 0x29:
            extended = True
        # first rewind 1 byte, as the first three bytes
        # are not very relevant anymore
        checkfile.seek(-1, os.SEEK_CUR)
        unpackedsize += 3

        # volume id
        checkbytes = checkfile.read(4)
        volumeid = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        partitionvolumelabel = ''
        filesystemtype = ''
        if extended:
            # partition volume label
            checkbytes = checkfile.read(11)
            try:
                partitionvolumelabel = checkbytes.decode()
            except UnicodeDecodeError:
                pass
            unpackedsize += 11

            # file system type
            checkbytes = checkfile.read(8)
            try:
                filesystemtype = checkbytes.decode()
            except UnicodeDecodeError:
                pass
            unpackedsize += 8
    else:
        isfat32 = True
        fattype = 'fat32'
        # logical per fat, with a few sanity checks
        if logicalperfat == 0:
            logicalperfat = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

    # sanity check for amount of logical sectors per FAT
    if not isfat32 and logicalperfat == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'logical sectors per FAT cannot be 0'}
        return {'status': False, 'error': unpackingerror}

    # FAT32 unsupported right now
    if isfat32:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'FAT32 unsupported at the moment'}
        return {'status': False, 'error': unpackingerror}

    # skip over the first sector
    checkfile.seek(offset + bytespersector)
    unpackedsize = bytespersector

    # then either process extra sectors (FAT32)
    # or skip over the other reserved sectors
    if isfat32:
        pass
    else:
        # skip reservedlogicalsectors - 1
        skipbytes = (reservedlogicalsectors - 1) * bytespersector
        if skipbytes != 0:
            if checkfile.tell() + skipbytes > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'reserved sectors cannot be outside file'}
                return {'status': False, 'error': unpackingerror}
            checkfile.seek(skipbytes, os.SEEK_CUR)
            unpackedsize += skipbytes

    # check if there is enough data for the FAT tables
    if checkfile.tell() + numberoffat * logicalperfat * bytespersector > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for FAT clusters'}
        return {'status': False, 'error': unpackingerror}

    clusterchainsperfat = {}

    # process the file allocation tables
    for i in range(0, numberoffat):
        clusterchainsperfat[i] = []
        endoffat = checkfile.tell() + logicalperfat * bytespersector
        # first byte in the FAT cluster has to be the same
        # the media descriptor
        checkbytes = checkfile.read(1)
        if ord(checkbytes) != mediadescriptor:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'FAT id does not match media descriptor'}
            return {'status': False, 'error': unpackingerror}
        # don't support anything by 0xf8 for now
        if ord(checkbytes) != 0xf8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'unsupported FAT id'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

        # now check to see whether this is FAT 12, FAT 16
        if not isfat32:
            checkbytes = checkfile.read(3)
            if checkbytes == b'\xff\xff\xff' and 'FAT12' not in filesystemtype:
                fattype = 'fat16'
            else:
                fattype = 'fat12'
            # don't support anything but FAT 16 right now
            if fattype != 'fat16':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'unsupported FAT version'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 3

            clustervals = [0, 0]
            while True:
                checkbytes = checkfile.read(2)
                if checkfile.tell() == endoffat:
                    unpackedsize += 2
                    break
                if checkfile.tell() > endoffat:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid FAT'}
                    return {'status': False, 'error': unpackingerror}
                clustervals.append(int.from_bytes(checkbytes, byteorder='little'))
                unpackedsize += 2

            # now recreate the cluster chains
            seenchainindexes = set([0, 1])
            chainstart = 1
            lastchainstart = len(clustervals)
            while True:
                chain = []
                chainstart = chainstart + 1
                if chainstart == lastchainstart:
                    break
                if chainstart in seenchainindexes:
                    continue

                # skip empty sectors
                if clustervals[chainstart] == 0:
                    continue

                # skip bad blocks
                if clustervals[chainstart] == 0xfff7:
                    continue

                # now walk the chain
                chainindex = chainstart
                while True:
                    # add the index to the chain
                    chain.append(chainindex)
                    seenchainindexes.add(chainindex)

                    # look at the next value
                    chainindex = clustervals[chainindex]
                    # end of chain, so exit
                    if chainindex == 0xffff:
                        break
                    # bad block, unsure what to do here
                    if chainindex == 0xfff7:
                        break
                    if chainindex == 0:
                        break
                clusterchainsperfat[i].append(chain)

    clustertochain = {}

    for i in clusterchainsperfat[0]:
        clustertochain[i[0]] = i

    # the cluster from which to read
    rootcluster = 0

    chainstoprocess = collections.deque()

    # FAT 16 has a separate root directory table with all the data
    if not isfat32:
        rootentry = ''
        rootextension = ''
        rootsize = 0

        # root directory is 32 bytes. The specifications say something
        # else, but files seen in the wild do not seem to follow the
        # specifcations.
        if checkfile.tell() + 32 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for root directory'}
            return {'status': False, 'error': unpackingerror}

        # process the root entry
        checkbytes = checkfile.read(8)
        if checkbytes[0] in [0, 0xe5]:
            # deleted or empty, so skip the rest of the root directory
            checkfile.seek(24, os.SEEK_CUR)
        else:
            if checkbytes[0] == 0x05:
                checkbytes[0] = 0xe5
            try:
                rootentry = checkbytes.decode().rstrip()
            except UnicodeDecodeError:
                pass
            checkbytes = checkfile.read(3)
            try:
                rootextension = checkbytes.decode().rstrip()
            except UnicodeDecodeError:
                pass
            if rootextension != '':
                fullname = '%s.%s' % (rootentry, rootextension)
            else:
                fullname = rootentry

            rootfileattributes = ord(checkfile.read(1))

            # skip 14 bytes, as they are not very relevant
            checkfile.seek(14, os.SEEK_CUR)

            # start of file cluster, has to be an existing cluster
            # unless long file names are used. TODO.
            checkbytes = checkfile.read(2)
            rootcluster = int.from_bytes(checkbytes, byteorder='little')
            if rootcluster not in clustertochain:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid cluster for root entry'}
                return {'status': False, 'error': unpackingerror}

            # file size
            checkbytes = checkfile.read(4)
            rootsize = int.from_bytes(checkbytes, byteorder='little')
            chainstoprocess.append((rootcluster, 'directory', fullname, 0, fullname))
        unpackedsize += 32

        # now skip the rest of the root entries
        skipbytes = (maxrootentries - 1) * 32
        if skipbytes > 0:
            unpackedsize += skipbytes
            checkfile.seek(skipbytes, os.SEEK_CUR)
    else:
        rootcluster = 2

    maxoffset = unpackedsize
    allowbrokenfat = True

    # process, but only if the root cluster is valid
    if rootcluster != 0:
        # now process all the entries, starting with the root cluster

        curdir = ''
        cursize = 0

        dataregionstart = checkfile.tell()
        clustersize = sectorspercluster * bytespersector

        while True:
            try:
                (startchain, chaintype, chaindir, chainsize, chainname) = chainstoprocess.popleft()
            except IndexError:
                break

            # first jump to the right place in the data region
            chainindex = 0
            curchain = clustertochain[startchain][chainindex]
            chainoffset = dataregionstart + (curchain - 2) * clustersize

            # chain cannot be outside of the file
            if not allowbrokenfat:
                if chainoffset + clustersize > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'file data cannot be outside of file system'}
                    return {'status': False, 'error': unpackingerror}

            checkfile.seek(chainoffset)

            if chaintype == 'file':
                # open the file for writing
                outfile_rel = os.path.join(unpackdir, chaindir, chainname)
                outfile_full = scanenvironment.unpack_path(outfile_rel)
                outfile = open(outfile_full, 'wb')

                # now walk the chain and write the contents of each cluster
                byteswritten = 0
                while True:
                    byteswritten += os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), clustersize)

                    maxoffset = max(maxoffset, checkfile.tell() + clustersize - offset)

                    chainindex += 1
                    if chainindex == len(clustertochain[startchain]):
                        break
                    curchain = clustertochain[startchain][chainindex]
                    chainoffset = dataregionstart + (curchain - 2) * clustersize
                    if not allowbrokenfat:
                        if chainoffset + clustersize > filesize:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'file data cannot be outside of file system'}
                            return {'status': False, 'error': unpackingerror}

                    checkfile.seek(chainoffset)
                outfile.flush()

                # truncate the file to the declared size
                # what if chainsize > bytes written? TODO.
                if byteswritten != chainsize:
                    outfile.seek(chainsize)
                    outfile.truncate()
                outfile.close()
                unpackedfilesandlabels.append((outfile_rel, []))

            elif chaintype == 'directory':
                direntries = []

                # use a local counter to keep track if all tracks in a sector
                # were read. If so, jump to the next sector in the chain.
                chainbytesread = 0
                while True:
                    if chainbytesread == clustersize:
                        chainindex += 1
                        if chainindex == len(clustertochain[startchain]):
                            break

                        # jump to the next sector in the chain
                        curchain = clustertochain[startchain][chainindex]
                        chainoffset = dataregionstart + (curchain - 2) * clustersize
                        if not allowbrokenfat:
                            if chainoffset + clustersize > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize,
                                                  'fatal': False,
                                                  'reason': 'file data cannot be outside of file system'}
                                return {'status': False, 'error': unpackingerror}

                        checkfile.seek(chainoffset)

                        # reset counter
                        chainbytesread = 0

                    # process all directory entries
                    checkbytes = checkfile.read(8)

                    if checkbytes[0] in [0, 0xe5]:
                        # deleted or empty, so skip the rest of the root directory
                        checkfile.seek(24, os.SEEK_CUR)
                    else:
                        if checkbytes[0] == 0x05:
                            checkbytes[0] = 0xe5
                        try:
                            entryname = checkbytes.decode().rstrip()
                        except UnicodeDecodeError:
                            pass
                        checkbytes = checkfile.read(3)
                        try:
                            entryextension = checkbytes.decode().rstrip()
                        except UnicodeDecodeError:
                            pass
                        fileattributes = ord(checkfile.read(1))

                        # skip 14 bytes, as they are not very relevant
                        checkfile.seek(14, os.SEEK_CUR)

                        # start of file cluster, has to be an existing cluster
                        checkbytes = checkfile.read(2)
                        cluster = int.from_bytes(checkbytes, byteorder='little')

                        # file size
                        checkbytes = checkfile.read(4)
                        entrysize = int.from_bytes(checkbytes, byteorder='little')

                        if entryname != '..' and entrysize != 0:
                            if cluster not in clustertochain:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize,
                                                  'fatal': False,
                                                  'reason': 'invalid cluster for entry'}
                                return {'status': False, 'error': unpackingerror}
                        if entryextension != '':
                            fullname = '%s.%s' % (entryname, entryextension)
                        else:
                            fullname = entryname
                        if fileattributes & 0x10 == 0x10:
                            # directory
                            if entryname != '..' and entryname != '.':
                                chainstoprocess.append((cluster, 'directory', os.path.join(chaindir, fullname), 0, fullname))
                            outfile_rel = os.path.join(unpackdir, chaindir, fullname)
                            outfile_full = scanenvironment.unpack_path(outfile_rel)
                            os.makedirs(os.path.dirname(outfile_full), exist_ok=True)
                            unpackedfilesandlabels.append((outfile_rel, ['directory']))
                        elif fileattributes & 0x20 == 0x20:
                            chainstoprocess.append((cluster, 'file', chaindir, entrysize, fullname))
                        else:
                            pass

                    chainbytesread += 32

    unpackedsize = maxoffset
    if offset == 0 and unpackedsize == filesize:
        labels.append("fat")
        labels.append('filesystem')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# coreboot file system
# https://www.coreboot.org/CBFS
#
# A CBFS file consists of various concatenated components.
def unpackCBFS(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/label coreboot file system images'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # open the file, skip the component magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # what follows is a list of components
    havecbfscomponents = False

    # there should be one master header, which defines a
    # few characteristics, such as the byte alignment. This
    # one should come first to be able to read the rest.
    seenmasterheader = False

    # It is assumed that the first block encountered is the master header
    while True:
        checkbytes = checkfile.read(8)
        if checkbytes != b'LARCHIVE':
            break
        unpackedsize += 8

        # length
        checkbytes = checkfile.read(4)
        componentlength = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        # type
        checkbytes = checkfile.read(4)
        componenttype = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        # checksum
        checkbytes = checkfile.read(4)
        checksum = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        # offset
        checkbytes = checkfile.read(4)
        componentoffset = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        if offset + componentoffset + componentlength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'data outside of file'}
            return {'status': False, 'error': unpackingerror}

        # "The difference between the size of the header and offset
        # is the size of the component name."
        checkbytes = checkfile.read(componentoffset - 24)
        if b'\x00' not in checkbytes:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid component name'}
            return {'status': False, 'error': unpackingerror}
        try:
            componentname = checkbytes.split(b'\x00')[0].decode()
        except:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid component name'}
            return {'status': False, 'error': unpackingerror}

        # store the current offset
        curoffset = checkfile.tell()

        # read the first four bytes of the payload to see
        # if this is the master header
        checkbytes = checkfile.read(4)
        if checkbytes == b'ORBC':
            if seenmasterheader:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'only one master header allowed'}
                return {'status': False, 'error': unpackingerror}

            # version
            checkbytes = checkfile.read(4)
            masterversion = int.from_bytes(checkbytes, byteorder='big')

            # romsize
            checkbytes = checkfile.read(4)
            romsize = int.from_bytes(checkbytes, byteorder='big')

            # check if the rom size isn't larger than the actual file.
            # As the master header won't be at the beginning of the file
            # the check should be against size of the entire file, not
            # starting at the offset, unless that is already part
            # of another file (TODO).
            if romsize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for image'}
                return {'status': False, 'error': unpackingerror}

            # boot block size
            checkbytes = checkfile.read(4)
            bootblocksize = int.from_bytes(checkbytes, byteorder='big')
            if bootblocksize > romsize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid boot block size'}
                return {'status': False, 'error': unpackingerror}

            # align, always 64 bytes
            checkbytes = checkfile.read(4)
            align = int.from_bytes(checkbytes, byteorder='big')

            if align != 64:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid alignment size'}
                return {'status': False, 'error': unpackingerror}

            # rom cannot be smaller than alignment
            if romsize < align:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid rom size'}
                return {'status': False, 'error': unpackingerror}

            # offset of first block
            checkbytes = checkfile.read(4)
            cbfsoffset = int.from_bytes(checkbytes, byteorder='big')
            if cbfsoffset > romsize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'offset of first block cannot be outside image'}
                return {'status': False, 'error': unpackingerror}

            if cbfsoffset > offset:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'offset of first block cannot be outside image'}
                return {'status': False, 'error': unpackingerror}

            seenmasterheader = True

        if not seenmasterheader:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'master header not seen'}
            return {'status': False, 'error': unpackingerror}

        # skip the data
        checkfile.seek(curoffset)
        checkfile.seek(componentlength, os.SEEK_CUR)

        # then read some more alignment bytes, if necessary
        if (checkfile.tell() - offset) % align != 0:
            padbytes = align - (checkfile.tell() - offset) % align
            checkfile.seek(padbytes, os.SEEK_CUR)

    if not seenmasterheader:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'master header not seen'}
        return {'status': False, 'error': unpackingerror}

    if checkfile.tell() - offset != romsize - cbfsoffset:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid coreboot image'}
        return {'status': False, 'error': unpackingerror}

    cbfsstart = offset - cbfsoffset
    if cbfsstart == 0 and romsize == filesize:
        labels.append("coreboot")
        checkfile.close()

        return {'status': True, 'length': romsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels, 'offset': cbfsstart}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.coreboot")
    outfile_full = scanenvironment.unpack_path(outfile_rel)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), cbfsstart, romsize)
    outfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((outfile_rel, ['coreboot', 'unpacked']))
    return {'status': True, 'length': romsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels, 'offset': cbfsstart}


# /usr/share/magic
# https://en.wikipedia.org/wiki/MINIX_file_system
# https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/fs/mfs
# https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/usr.sbin/mkfs.mfs/v1l
def unpackMinix1L(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack Minix V1 file systems (extended Linux variant)'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # boot block and super block are both 1K
    if offset + 2048 > filesize:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for superblock'}
        return {'status': False, 'error': unpackingerror}

    # open the file
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    blocksize = 1024

    # the first block is the boot block, which can
    # be skipped
    checkfile.seek(blocksize, os.SEEK_CUR)
    unpackedsize += blocksize

    # Then read the superblock. All this data is little endian.

    # the number of inodes
    checkbytes = checkfile.read(2)
    nrinodes = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # there always has to be at least one inode
    if nrinodes == 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough inodes'}
        return {'status': False, 'error': unpackingerror}

    # the number of zones
    checkbytes = checkfile.read(2)
    zones = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # inode bitmap blocks
    checkbytes = checkfile.read(2)
    inodeblocks = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # zone bitmap blocks
    checkbytes = checkfile.read(2)
    zoneblocks = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # first data zone
    checkbytes = checkfile.read(2)
    firstdatazone = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # log zone size
    checkbytes = checkfile.read(2)
    logzonesize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # max size
    checkbytes = checkfile.read(4)
    maxsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # magic, skip
    checkfile.seek(2, os.SEEK_CUR)
    unpackedsize += 2

    # state
    checkbytes = checkfile.read(2)
    minixstate = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # some sanity checks
    # superblock is followed by the inode bitmap and zone bitmap
    # and then by the inodes. Each inode is 32 bytes.
    if offset + 2048 + (inodeblocks + zoneblocks) * blocksize + nrinodes * 32 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for bitmaps or inodes'}
        return {'status': False, 'error': unpackingerror}

    # skip over the bitmaps
    checkfile.seek(offset + 2048 + (inodeblocks + zoneblocks) * blocksize)
    unpackedsize = 2048 + (inodeblocks + zoneblocks) * blocksize

    # store the (relative) end of the inodes
    endofinodes = checkfile.tell() + 32 * nrinodes - offset

    # sanity check: data zone cannot be earlier than end of inodes
    if firstdatazone * blocksize < endofinodes:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'data zones cannot be before inodes'}
        return {'status': False, 'error': unpackingerror}

    inodes = {}

    # Next are the inodes. The root inode is always 1.
    for i in range(1, nrinodes+1):
        # first the mode
        checkbytes = checkfile.read(2)
        inodemode = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        if i == 1:
            if inodemode == 0:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'no valid data for inode 1'}
                return {'status': False, 'error': unpackingerror}
            if not stat.S_ISDIR(inodemode):
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'wrong type for inode 1'}
                return {'status': False, 'error': unpackingerror}

        # then the uid
        checkbytes = checkfile.read(2)
        inodeuid = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        # the inode size
        checkbytes = checkfile.read(4)
        inodesize = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        # the inode time
        checkbytes = checkfile.read(4)
        inodetime = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        # the inode gid
        checkbytes = checkfile.read(1)
        inodegid = ord(checkbytes)
        unpackedsize += 1

        # the number of links
        checkbytes = checkfile.read(1)
        inodenrlinks = ord(checkbytes)
        unpackedsize += 1

        # 9 izones. First 7 are direct zones,
        # 8th is for indirect zones, 9th is for
        # double indirect zones.
        zones = []
        for z in range(0, 9):
            checkbytes = checkfile.read(2)
            inodezone = int.from_bytes(checkbytes, byteorder='little')
            zones.append(inodezone)
            unpackedsize += 2
        if inodemode != 0:
            inodes[i] = {'mode': inodemode, 'uid': inodeuid, 'size': inodesize,
                         'time': inodetime, 'gid': inodegid,
                         'links': inodenrlinks, 'zones': zones}

    # map inode to name
    inodetoname = {}

    # relative root
    inodetoname[1] = ''

    dataunpacked = False

    maxoffset = blocksize * 2

    # now process the inodes. Actually only the inodes that
    # are in the inode bitmap should be looked at. This is a TODO.
    for i in inodes:
        if i not in inodetoname:
            # dangling inode?
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unknown inode'}
            return {'status': False, 'error': unpackingerror}
        if stat.S_ISREG(inodes[i]['mode']):
            outfile_rel = os.path.join(unpackdir, inodetoname[i])
            outfile_full = scanenvironment.unpack_path(outfile_rel)
            # open the file for writing
            outfile = open(outfile_full, 'wb')
            seenzones = 1
            zonestowrite = []
            for z in inodes[i]['zones']:
                if z == 0:
                    break

                # the zone cannot be smaller than the first data zone
                if z < firstdatazone:
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid zone number'}
                    return {'status': False, 'error': unpackingerror}

                # zone has to be in the file
                if offset + z * blocksize + blocksize > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'not enough data for zone'}
                    return {'status': False, 'error': unpackingerror}

                if seenzones == 8:
                    # this is an indirect zone, containing more data
                    # First seek to the right zone offset
                    checkfile.seek(offset + z * blocksize)

                    # Then get the zone numbers. Like the direct zone
                    # numbers these are two bytes.
                    for iz in range(0, 512):
                        checkbytes = checkfile.read(2)
                        inodezone = int.from_bytes(checkbytes, byteorder='little')
                        if inodezone != 0:
                            # the zone cannot be smaller
                            # than the first data zone
                            if inodezone < firstdatazone:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfile_full)
                                unpackingerror = {'offset': offset,
                                                  'fatal': False,
                                                  'reason': 'invalid zone number'}
                                return {'status': False, 'error': unpackingerror}

                            # zone has to be in the file
                            if offset + inodezone * blocksize + blocksize > filesize:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfile_full)
                                unpackingerror = {'offset': offset,
                                                  'fatal': False,
                                                  'reason': 'not enough data for zone'}
                                return {'status': False, 'error': unpackingerror}

                            # write the data to the output file
                            zonestowrite.append(inodezone)
                elif seenzones == 9:
                    # this is a double indirect zone
                    # First seek to the right zone offset
                    checkfile.seek(offset + z * blocksize)

                    # Then get the indirect zone numbers. Like the direct zone
                    # numbers these are two bytes.
                    indirectzones = []
                    for iz in range(0, 512):
                        checkbytes = checkfile.read(2)
                        inodezone = int.from_bytes(checkbytes, byteorder='little')
                        if inodezone != 0:
                            # the zone cannot be smaller
                            # than the first data zone
                            if inodezone < firstdatazone:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfile_full)
                                unpackingerror = {'offset': offset,
                                                  'fatal': False,
                                                  'reason': 'invalid zone number'}
                                return {'status': False, 'error': unpackingerror}

                            # zone has to be in the file
                            if offset + inodezone * blocksize + blocksize > filesize:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfile_full)
                                unpackingerror = {'offset': offset,
                                                  'fatal': False,
                                                  'reason': 'not enough data for zone'}
                                return {'status': False, 'error': unpackingerror}
                            indirectzones.append(inodezone)

                    # now process each indirect zone
                    for iz in indirectzones:
                        checkfile.seek(offset + iz * blocksize)

                        # then read each indirect zone
                        for izz in range(0, 512):
                            checkbytes = checkfile.read(2)
                            inodezone = int.from_bytes(checkbytes, byteorder='little')
                            if inodezone != 0:
                                # the zone cannot be smaller than
                                # the first data zone
                                if inodezone < firstdatazone:
                                    checkfile.close()
                                    outfile.close()
                                    os.unlink(outfile_full)
                                    unpackingerror = {'offset': offset,
                                                      'fatal': False,
                                                      'reason': 'invalid zone number'}
                                    return {'status': False, 'error': unpackingerror}

                                # zone has to be in the file
                                if offset + inodezone * blocksize + blocksize > filesize:
                                    checkfile.close()
                                    outfile.close()
                                    os.unlink(outfile_full)
                                    unpackingerror = {'offset': offset,
                                                      'fatal': False,
                                                      'reason': 'not enough data for zone'}
                                    return {'status': False, 'error': unpackingerror}

                                zonestowrite.append(inodezone)
                else:
                    zonestowrite.append(z)
                seenzones += 1

            # write all the data
            for z in zonestowrite:
                dataoffset = offset + z * blocksize
                os.sendfile(outfile.fileno(), checkfile.fileno(), dataoffset, blocksize)
                maxoffset = max(maxoffset, z * blocksize + blocksize)
            outfile.truncate(inodes[i]['size'])
            outfile.close()
            unpackedfilesandlabels.append((outfile_rel, ['directory']))
            dataunpacked = True
        elif stat.S_ISCHR(inodes[i]['mode']):
            pass
        elif stat.S_ISBLK(inodes[i]['mode']):
            pass
        elif stat.S_ISFIFO(inodes[i]['mode']):
            pass
        elif stat.S_ISSOCK(inodes[i]['mode']):
            pass
        elif stat.S_ISLNK(inodes[i]['mode']):
            outfile_rel = os.path.join(unpackdir, inodetoname[i])
            outfile_full = scanenvironment.unpack_path(outfile_rel)
            destinationname = ''
            for z in inodes[i]['zones']:
                if z == 0:
                    break
                dataoffset = offset + z * blocksize
                checkfile.seek(dataoffset)
                checkbytes = checkfile.read(blocksize)
                try:
                    destinationname += checkbytes.split(b'\x00', 1)[0].decode()
                except:
                    destinationname = ''
                    break
                maxoffset = max(maxoffset, z * blocksize + blocksize)
            if destinationname != '':
                os.symlink(destinationname, outfile_full)
            unpackedfilesandlabels.append((outfile_rel, ['symbolic link']))
            dataunpacked = True
        elif stat.S_ISDIR(inodes[i]['mode']):
            seenzones = 1
            curdirname = inodetoname[i]
            if curdirname != '':
                outfile_rel = os.path.join(unpackdir, curdirname)
                outfile_full = scanenvironment.unpack_path(outfile_rel)
                os.makedirs(outfile_full)
                dataunpacked = True
            for z in inodes[i]['zones']:
                if z == 0:
                    break
                if seenzones == 8:
                    # this is an indirect zone, not supported yet
                    break
                if seenzones == 9:
                    # this is a double indirect zone, not supported yet
                    break

                # the zone cannot be smaller than the first data zone
                if z < firstdatazone:
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid zone number'}
                    return {'status': False, 'error': unpackingerror}

                # zone has to be in the file
                if offset + z * blocksize + blocksize > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'not enough data for zone'}
                    return {'status': False, 'error': unpackingerror}

                maxoffset = max(maxoffset, z * blocksize + blocksize)

                # seek to the start of the zone and process
                # all entries.
                checkfile.seek(offset + z * blocksize)
                for r in range(0, blocksize//32):
                    checkbytes = checkfile.read(2)
                    inodenr = int.from_bytes(checkbytes, byteorder='little')

                    checkbytes = checkfile.read(30)

                    if inodenr == 0:
                        continue
                    try:
                        inodename = checkbytes.split(b'\x00', 1)[0].decode()
                    except:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False,
                                          'reason': 'invalid inode name'}
                        return {'status': False, 'error': unpackingerror}
                    if inodename != '.' and inodename != '..':
                        inodetoname[inodenr] = os.path.join(curdirname, inodename)
                        # now check to see if the inode is a directory
                        if inodenr not in inodes:
                            # dangling inode?
                            checkfile.close()
                            unpackingerror = {'offset': offset, 'fatal': False,
                                              'reason': 'invalid inode'}
                            return {'status': False, 'error': unpackingerror}
                seenzones += 1

    if not dataunpacked:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid Minix file system'}
        return {'status': False, 'error': unpackingerror}

    # It is very difficult to distinguish padding from actual
    # file system data, as unused bytes are NUL bytes and no
    # file system length is actually recorded in the superblock.
    if offset == 0 and maxoffset == filesize:
        labels.append('minix')
        labels.append('filesystem')

    return {'status': True, 'length': maxoffset, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# Linux kernel: Documentation/filesystems/romfs.txt
def unpackRomfs(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a romfs file system'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # open the file, skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    # then the file size, big endian
    checkbytes = checkfile.read(4)
    romsize = int.from_bytes(checkbytes, byteorder='big')
    if offset + romsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'romfs cannot extend past end of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # then the checksum of the first 512 bytes, skip for now
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    # the file name, padded on a 16 byte boundary
    romname = b''
    while True:
        checkbytes = checkfile.read(16)
        if len(checkbytes) != 16:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for name'}
            return {'status': False, 'error': unpackingerror}
        romname += checkbytes
        unpackedsize += 16
        if b'\x00' in checkbytes:
            break

    try:
        romname = romname.split(b'\x00', 1)[0].decode()
    except:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid name for romfs'}
        return {'status': False, 'error': unpackingerror}

    # keep a mapping from offsets to parent names
    offsettoparent = {}

    # and a mapping from offsets to current names (used for hard links)
    offsettoname = {}

    # keep a deque with which offset/parent directory pairs
    offsets = collections.deque()

    # then the file headers, with data
    curoffset = checkfile.tell() - offset
    curcwd = ''
    offsets.append((curoffset, curcwd))

    # now keep processing offsets, until none
    # are left to process.
    maxoffset = checkfile.tell() - offset
    while True:
        try:
            (curoffset, curcwd) = offsets.popleft()
        except:
            break
        checkfile.seek(offset + curoffset)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for file data'}
            return {'status': False, 'error': unpackingerror}

        unpackedsize += 4

        # the location of the next header, except for the last 4 bits
        nextheader = int.from_bytes(checkbytes, byteorder='big') & 4294967280

        # next header cannot be outside of the file
        if offset + nextheader > filesize:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'next offset cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}

        # flag to see if the file is executable, can be ignored for now
        execflag = int.from_bytes(checkbytes, byteorder='big') & 8

        # mode info, ignore for now
        modeinfo = int.from_bytes(checkbytes, byteorder='big') & 7

        # spec.info
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for file special info'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        specinfo = int.from_bytes(checkbytes, byteorder='big')

        # sanity checks
        if modeinfo == 1:
            pass

        # read the file size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for file size'}
            return {'status': False, 'error': unpackingerror}
        inodesize = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        # checksum, not used
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for file checksum'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # file name, 16 byte boundary, padded
        inodename = b''
        while True:
            checkbytes = checkfile.read(16)
            if len(checkbytes) != 16:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for file name'}
                return {'status': False, 'error': unpackingerror}
            inodename += checkbytes
            unpackedsize += 16
            if b'\x00' in checkbytes:
                break

        try:
            inodename = inodename.split(b'\x00', 1)[0].decode()
        except:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid file name'}
            return {'status': False, 'error': unpackingerror}

        # the file data cannot be outside of the file
        if checkfile.tell() + inodesize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'file cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}

        if inodename != '.' and inodename != '..':
            offsettoname[curoffset] = inodename

        # now process the inode
        if modeinfo == 0:
            # hard link, target is in spec.info
            if inodename != '.' and inodename != '..':
                if specinfo not in offsettoname:
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid link'}
                    return {'status': False, 'error': unpackingerror}
                sourcetargetname = offsettoname[specinfo]
                if os.path.isabs(sourcetargetname):
                    sourcetargetname = os.path.relpath(sourcetargetname, '/')
                sourcetargetname = os.path.normpath(os.path.join(unpackdir, sourcetargetname))

                outfile_rel = os.path.join(unpackdir, curcwd, inodename)
                outfile_full = scanenvironment.unpack_path(outfile_rel)

                os.link(sourcetargetname, outfile_full)
                unpackedfilesandlabels.append((outfile_rel, ['hardlink']))
        elif modeinfo == 1:
            # directory: the next header points
            # to the first file header.
            if offset + specinfo > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'next offset cannot be outside of file'}
                return {'status': False, 'error': unpackingerror}
            if inodename != '.' and inodename != '..':
                outfile_rel = os.path.join(unpackdir, curcwd, inodename)
                outfile_full = scanenvironment.unpack_path(outfile_rel)
                os.mkdir(outfile_full)
                offsets.append((specinfo, os.path.join(curcwd, inodename)))
                unpackedfilesandlabels.append((outfile_rel, ['directory']))
        elif modeinfo == 2:
            # regular file
            if specinfo != 0:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid value for specinfo'}
                return {'status': False, 'error': unpackingerror}
            outfile_rel = os.path.join(unpackdir, curcwd, inodename)
            outfile_full = scanenvironment.unpack_path(outfile_rel)
            outfile = open(outfile_full, 'wb')
            os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), inodesize)
            outfile.close()
            unpackedfilesandlabels.append((outfile_rel, []))
        elif modeinfo == 3:
            # symbolic link
            if specinfo != 0:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid value for specinfo'}
                return {'status': False, 'error': unpackingerror}
            checkbytes = checkfile.read(inodesize)
            try:
                sourcetargetname = checkbytes.split(b'\x00', 1)[0].decode()
            except:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid symbolic link'}
                return {'status': False, 'error': unpackingerror}
            if len(sourcetargetname) == 0:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid symbolic link'}
                return {'status': False, 'error': unpackingerror}
            if os.path.isabs(sourcetargetname):
                sourcetargetname = os.path.relpath(sourcetargetname, '/')
                sourcetargetname = os.path.normpath(os.path.join(unpackdir, sourcetargetname))

            outfile_rel = os.path.join(unpackdir, curcwd, inodename)
            outfile_full = scanenvironment.unpack_path(outfile_rel)

            os.symlink(sourcetargetname, outfile_full)
            unpackedfilesandlabels.append((outfile_rel, ['symbolic link']))
        elif modeinfo == 4:
            # block device
            pass
        elif modeinfo == 5:
            # character device
            pass
        elif modeinfo == 6:
            # socket
            if specinfo != 0:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid value for specinfo'}
                return {'status': False, 'error': unpackingerror}
        elif modeinfo == 7:
            # fifo
            if specinfo != 0:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid value for specinfo'}
                return {'status': False, 'error': unpackingerror}

        maxoffset = max(maxoffset, curoffset + inodesize)
        # no more files
        if nextheader != 0:
            offsets.append((nextheader, curcwd))

    # the maximum offset cannot be larger than the declared rom size
    if maxoffset > romsize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'maximum offset larger than declared rom size'}
        return {'status': False, 'error': unpackingerror}

    # romfs file systems are aligned on a 1024 byte boundary
    if romsize % 1024 != 0:
        paddingbytes = 1024 - romsize % 1024
        maxoffset = romsize + paddingbytes

    if offset == 0 and maxoffset == filesize:
        labels.append('romfs')
        labels.append('filesystem')

    return {'status': True, 'length': maxoffset, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# Linux kernel: fs/cramfs/README
# needs recent version of util-linux that supports --extract
def unpack_cramfs(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a cramfs file system'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # minimum of 1 block of 4096 bytes
    if offset + 4096 > filesize:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # read the magic to see what the endianness is
    checkbytes = checkfile.read(4)
    if checkbytes == b'\x45\x3d\xcd\x28':
        byteorder = 'little'
        bigendian = False
    else:
        byteorder = 'big'
        bigendian = True
    unpackedsize += 4

    # length in bytes
    checkbytes = checkfile.read(4)
    cramfssize = int.from_bytes(checkbytes, byteorder=byteorder)
    if offset + cramfssize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'declared size larger than file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # feature flags
    checkbytes = checkfile.read(4)
    featureflags = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    if featureflags & 1 == 1:
        cramfsversion = 2
    else:
        cramfsversion = 0

    # currently only version 2 is supported
    if cramfsversion == 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported cramfs version'}
        return {'status': False, 'error': unpackingerror}

    # reserved for future use, skip
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # signature
    checkbytes = checkfile.read(16)
    if checkbytes != b'Compressed ROMFS':
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid signature'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 16

    # cramfs_info struct (32 bytes)
    # crc32
    checkbytes = checkfile.read(4)
    cramfscrc32 = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # edition
    checkbytes = checkfile.read(4)
    cramfsedition = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # blocks
    checkbytes = checkfile.read(4)
    cramfsblocks = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # files
    checkbytes = checkfile.read(4)
    cramfsfiles = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # user defined name
    checkbytes = checkfile.read(16)
    try:
        volumename = checkbytes.split(b'\x00', 1)[0].decode()
    except UnicodeDecodeError:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid volume name'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 16

    # then process the inodes.

    # keep a mapping of inode numbers to metadata
    # and a reverse mapping from offset to inode
    inodes = {}
    offsettoinode = {}
    dataoffsettoinode = {}

    # See defines in Linux kernel include/uapi/linux/cramfs_fs.h
    # for the width/length of modes, lengths, etc.
    for inode in range(0, cramfsfiles):
        # store the current offset, as it is used by directories
        curoffset = checkfile.tell() - offset

        # 2 bytes mode width, 2 bytes uid width
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for inode'}
            return {'status': False, 'error': unpackingerror}
        inodemode = int.from_bytes(checkbytes, byteorder=byteorder)
        unpackedsize += 2

        # determine the kind of file
        if stat.S_ISDIR(inodemode):
            mode = 'directory'
        elif stat.S_ISCHR(inodemode):
            mode = 'chardev'
        elif stat.S_ISBLK(inodemode):
            mode = 'blockdev'
        elif stat.S_ISREG(inodemode):
            mode = 'file'
        elif stat.S_ISFIFO(inodemode):
            mode = 'fifo'
        elif stat.S_ISLNK(inodemode):
            mode = 'symlink'
        elif stat.S_ISSOCK(inodemode):
            mode = 'socket'

        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for inode'}
            return {'status': False, 'error': unpackingerror}
        inodeuid = int.from_bytes(checkbytes, byteorder=byteorder)
        unpackedsize += 2

        # 3 bytes size width, 1 bytes gid width
        checkbytes = checkfile.read(3)
        if len(checkbytes) != 3:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for inode'}
            return {'status': False, 'error': unpackingerror}

        # size of the decompressed inode
        inodesize = int.from_bytes(checkbytes, byteorder=byteorder)
        unpackedsize += 3

        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for inode'}
            return {'status': False, 'error': unpackingerror}
        inodegid = int.from_bytes(checkbytes, byteorder=byteorder)
        unpackedsize += 1

        # length of the name and offset. The first 6 bits are for
        # the name length (divided by 4), the last 26 bits for the
        # offset of the data (divided by 4). This is regardless of
        # the endianness!
        # The name is padded to 4 bytes. Because the original name length
        # is restored by multiplying with 4 there is no need for a
        # check for padding.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for inode'}
            return {'status': False, 'error': unpackingerror}
        namelenbytes = int.from_bytes(checkbytes, byteorder=byteorder)
        unpackedsize += 4

        if bigendian:
            # get the most significant bits and then shift 26 bits
            namelength = ((namelenbytes & 4227858432) >> 26) * 4

            # 0b11111111111111111111111111 = 67108863
            dataoffset = (namelenbytes & 67108863) * 4
        else:
            # 0b111111 = 63
            namelength = (namelenbytes & 63) * 4

            # get the bits, then shift 6 bits
            dataoffset = ((namelenbytes & 67108863) >> 6) * 4

        # the data cannot be outside of the file
        if offset + dataoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'data cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}

        # if this is the root node there won't be any data
        # following, so continue with the next inode.
        if inode == 0:
            continue

        if namelength == 0:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'cannot have zero length filename'}
            return {'status': False, 'error': unpackingerror}

        checkbytes = checkfile.read(namelength)
        try:
            inodename = checkbytes.split(b'\x00', 1)[0].decode()
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid filename'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += namelength

        inodes[inode] = {'name': inodename, 'mode': mode, 'offset': curoffset,
                         'dataoffset': dataoffset, 'uid': inodeuid,
                         'gid': inodegid, 'size': inodesize}

        offsettoinode[curoffset] = inode

        if dataoffset != 0:
            dataoffsettoinode[dataoffset] = inode

    inodeoffsettodirectory = {}

    # for now unpack using fsck.cramfs from util-linux. In the future
    # this should be replaced by an own unpacker.

    # now verify the data
    for inode in inodes:
        # don't recreate device files
        if inodes[inode]['mode'] == 'blockdev':
            continue
        if inodes[inode]['mode'] == 'chardev':
            continue
        if inodes[inode]['mode'] == 'file':
            pass
        elif inodes[inode]['mode'] == 'directory':
            # the data offset points to the offset of
            # the first inode in the directory
            if inodes[inode]['dataoffset'] != 0:
                # verify if there is a valid inode
                if inodes[inode]['dataoffset'] not in offsettoinode:
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid directory entry'}
                    return {'status': False, 'error': unpackingerror}

    havetmpfile = False

    # unpack in a temporary directory, as fsck.cramfs expects
    # to create the directory itself, but the unpacking directory
    # already exists.

    # first get a temporary name
    cramfsunpackdirectory = tempfile.mkdtemp(dir=temporarydirectory)

    # remove the directory. Possible race condition?
    shutil.rmtree(cramfsunpackdirectory)

    if offset == 0 and cramfssize == filesize:
        checkfile.close()
        p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % cramfsunpackdirectory, filename_full],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, cramfssize)
        os.fdopen(temporaryfile[0]).close()
        checkfile.close()
        havetmpfile = True

        p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % cramfsunpackdirectory, temporaryfile[1]],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (outputmsg, errormsg) = p.communicate()

    # clean up
    if havetmpfile:
        os.unlink(temporaryfile[1])

    if p.returncode != 0:
        # clean up the temporary directory. It could be that
        # fsck.cramfs actually didn't create the directory due to
        # other errors, such as a CRC error.
        if os.path.exists(cramfsunpackdirectory):
            shutil.rmtree(cramfsunpackdirectory)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot unpack cramfs'}
        return {'status': False, 'error': unpackingerror}

    # move contents of the unpacked file system
    foundfiles = os.listdir(cramfsunpackdirectory)
    curcwd = os.getcwd()

    os.chdir(cramfsunpackdirectory)
    for l in foundfiles:
        try:
            shutil.move(l, unpackdir_full, copy_function=local_copy2)
        except Exception as e:
            # TODO: report
            # possibly not all files can be copied.
            pass

    os.chdir(curcwd)

    # clean up of directory
    shutil.rmtree(cramfsunpackdirectory)

    # now add everything that was unpacked
    dirwalk = os.walk(unpackdir_full)
    for direntries in dirwalk:
        # make sure all subdirectories and files can be accessed
        for entryname in direntries[1]:
            fullfilename = os.path.join(direntries[0], entryname)
            if not os.path.islink(fullfilename):
                os.chmod(fullfilename, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            relfilename = scanenvironment.rel_unpack_path(fullfilename)
            unpackedfilesandlabels.append((relfilename, []))
        for entryname in direntries[2]:
            fullfilename = os.path.join(direntries[0], entryname)
            relfilename = scanenvironment.rel_unpack_path(fullfilename)
            unpackedfilesandlabels.append((relfilename, []))

    if offset == 0 and cramfssize == filesize:
        labels.append('cramfs')
        labels.append('filesystem')

    return {'status': True, 'length': cramfssize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}
