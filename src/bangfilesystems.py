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
# Copyright 2018-2022 - Armijn Hemel
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
import gzip
import stat
import subprocess
import json
import re
import pathlib
import lzo

encodingstotranslate = ['utf-8', 'ascii', 'latin-1', 'euc_jp', 'euc_jis_2004',
                        'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                        'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                        'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                        'shift_jis_2004', 'shift_jisx0213']


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
def unpack_iso9660(fileresult, scanenvironment, offset, unpackdir):
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

    # http://fileformats.archiveteam.org/wiki/Apple_ISO_9660_extensions
    is_apple_iso = False

    isobuffer = bytearray(2048)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

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

                            if signatureword == b'AA':
                                is_apple_iso = True

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
                                if not havesusp and not is_apple_iso:
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
                                if signatureword == b'RR':
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
def unpack_ext2(fileresult, scanenvironment, offset, unpackdir):
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

        # socket, symbolic link, regular, block device, directory
        # charactter device, FIFO/pipe
        octals = [('s', 0o140000), ('l', 0o120000), ('-', 0o100000),
                  ('b', 0o60000), ('d', 0o40000), ('c', 0o10000),
                  ('p', 0o20000)]

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
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
            try:
                filemode = int(filemode, base=8)
            except ValueError:
                # newer versions of e2tools (starting 0.1.0) pretty print
                # the file mode instead of printing a number so recreate it
                if len(filemode) != 10:
                     unpackingerror = {'offset': offset, 'fatal': False,
                                       'reason': 'e2ls error'}
                     return {'status': False, 'error': unpackingerror}

                # instantiate the file mode and look at the first character
                # as that is the only one used during checks.
                filemode = filemode.decode()
                new_filemode = 0
                for fm in octals:
                    if filemode[0] == fm[0]:
                        new_filemode = fm[1]
                        break

                filemode = new_filemode

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


# FAT file system
# https://en.wikipedia.org/wiki/File_Allocation_Table
# https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
def unpack_fat(fileresult, scanenvironment, offset, unpackdir):
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

    reservedblocks = [0xfff0, 0xfff1, 0xfff2, 0xfff3, 0xfff4, 0xfff5, 0xfff6]

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
                    if chainindex in reservedblocks:
                        break

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
                            # directory, don't add . and .. to the chain to process
                            if entryname != '..' and entryname != '.':
                                chainstoprocess.append((cluster, 'directory', os.path.join(chaindir, fullname), 0, fullname))
                            # no need to process '.', but for some reason some
                            # data from '..' has to be processed
                            if entryname != '.':
                                outfile_rel = os.path.join(unpackdir, chaindir, fullname)
                                outfile_full = scanenvironment.unpack_path(outfile_rel)
                                os.makedirs(os.path.dirname(outfile_full), exist_ok=True)
                                if entryname != '..':
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


# Linux kernel: Documentation/filesystems/romfs.txt
def unpack_romfs(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a romfs file system'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

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

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

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
                sourcetargetname = os.path.normpath(os.path.join(unpackdir, curcwd, sourcetargetname))
                sourcetargetname = scanenvironment.unpack_path(sourcetargetname)

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
