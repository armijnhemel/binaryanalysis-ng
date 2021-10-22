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
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''Built in carvers/verifiers/unpackers for various Android formats (except
certain formats such as APK, which are with other unpackers).'''

import os
import tempfile
import struct
import zlib
import hashlib
import re
import pathlib
import brotli

# own modules
import bangunpack

encodingstotranslate = ['utf-8', 'ascii', 'latin-1', 'euc_jp', 'euc_jis_2004',
                        'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                        'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                        'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                        'shift_jis_2004', 'shift_jisx0213']


# Some Android firmware updates are distributed as sparse data images.
# Given a data image and a transfer list data on an Android device is
# block wise added, replaced, erased, or zeroed.
#
# The Android sparse data image format is documented in the Android
# source code tree:
#
# https://android.googlesource.com/platform/bootable/recovery/+/4f81130039f6a312eba2027b3594a2be282f6b3a/updater/blockimg.cpp#1980
#
# Test files can be downloaded from LineageOS, for example:
#
# lineage-14.1-20180410-nightly-FP2-signed.zip
#
# Note: this is different to the Android sparse image format.
def unpack_android_sparse_data(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack an Android sparse data file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    # TODO
    # if the file is compressed with Brotli it should first
    # be decompressed before it can be processed

    # for each .new.dat file there has to be a corresponding
    # .transfer.list file as well.
    transferfile = filename_full.parent / (filename_full.name[:-8] + ".transfer.list")
    if not transferfile.exists():
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'transfer list not found'}
        return {'status': False, 'error': unpackingerror}

    # open the transfer list in text mode, not in binary mode
    transferlist = open(transferfile, 'r')
    transferlistlines = list(map(lambda x: x.strip(), transferlist.readlines()))
    transferlist.close()

    if len(transferlistlines) < 4:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough entries in transer list'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize = 0

    # first line is the version number, see comment here:
    # https://android.googlesource.com/platform/bootable/recovery/+/master/updater/blockimg.cpp#1628
    try:
        versionnumber = int(transferlistlines[0])
    except ValueError:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid transfer list version number'}
        return {'status': False, 'error': unpackingerror}

    if versionnumber > 4:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid version number'}
        return {'status': False, 'error': unpackingerror}

    if versionnumber < 2:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'only transfer list version 2-4 supported'}
        return {'status': False, 'error': unpackingerror}

    # the next line is the amount of blocks (1 block is 4096 bytes)
    # that will be copied to the output. This does not necessarily
    # anything about the size of the output file as it might not include
    # the blocks such as erase or zero, so it can be safely ignored.
    try:
        outputblocks = int(transferlistlines[1])
    except ValueError:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid number for blocks to be written'}
        return {'status': False, 'error': unpackingerror}

    # then two lines related to stash entries which are only used by
    # Android during updates to prevent flash space from overflowing,
    # so can safely be ignored here.
    try:
        stashneeded = int(transferlistlines[2])
    except ValueError:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid number for simultaneous stash entries needed'}
        return {'status': False, 'error': unpackingerror}

    try:
        maxstash = int(transferlistlines[2])
    except ValueError:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid number for maximum stash entries'}
        return {'status': False, 'error': unpackingerror}

    # a list of commands recognized
    validtransfercommands = set(['new', 'zero', 'erase', 'free', 'stash'])

    transfercommands = []

    # store the maximum block number
    maxblock = 0

    # then parse the rest of the lines to see if they are valid
    for l in transferlistlines[4:]:
        transfersplit = l.split(' ')
        if len(transfersplit) != 2:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid line in transfer list'}
            return {'status': False, 'error': unpackingerror}
        (transfercommand, transferblocks) = transfersplit
        if transfercommand not in validtransfercommands:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unsupported command in transfer list'}
            return {'status': False, 'error': unpackingerror}
        transferblockssplit = transferblocks.split(',')
        if len(transferblockssplit) % 2 == 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        # first entry is the number of blocks on the rest of line
        try:
            transferblockcount = int(transferblockssplit[0])
        except ValueError:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        if not transferblockcount == len(transferblockssplit[1:]):
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        # then check the rest of the numbers
        try:
            blocks = []
            for b in transferblockssplit[1:]:
                blocknr = int(b)
                blocks.append(blocknr)
                maxblock = max(maxblock, blocknr)
        except ValueError:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        # store the transfer commands
        transfercommands.append((transfercommand, blocks))

    # block size is set to 4096 in the Android source code
    blocksize = 4096

    # cut the extension '.new.dat' from the file name unless the file
    # name is the extension (as there would be a zero length name).
    if len(filename_full.stem) == 0:
        outputfile_rel = os.path.join(unpackdir, "unpacked-from-android-sparse-data")
    else:
        outputfile_rel = os.path.join(unpackdir, filename_full.stem)
    outputfile_full = scanenvironment.unpack_path(outputfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # first create the targetfile
    targetfile = open(outputfile_full, 'wb')

    # make sure that the target file is large enough.
    # On Linux truncate() will zero fill the targetfile.
    targetfile.truncate(maxblock*blocksize)

    # then seek to the beginning of the target file
    targetfile.seek(0)

    # open the source file
    checkfile = open(filename_full, 'rb')

    checkfile.seek(0)

    # then process all the commands. "zero" is not interesting as
    # the underlying file has already been zero filled.
    # erase is not very interesting either.
    for c in transfercommands:
        (transfercommand, blocks) = c
        if transfercommand == 'new':
            for b in range(0, len(blocks), 2):
                targetfile.seek(blocks[b]*blocksize)
                os.sendfile(targetfile.fileno(), checkfile.fileno(), None, (blocks[b+1] - blocks[b]) * blocksize)
        else:
            pass

    targetfile.close()
    checkfile.close()

    unpackedsize = filesize

    labels += ['androidsparsedata', 'android']
    unpackedfilesandlabels.append((outputfile_rel, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_android_sparse_data.extensions = ['.new.dat']
unpack_android_sparse_data.pretty = 'androidsparsedata'


# Android backup files
#
# Description of the format here:
#
# https://nelenkov.blogspot.nl/2012/06/unpacking-android-backups.html
# http://web.archive.org/web/20180425072922/https://nelenkov.blogspot.nl/2012/06/unpacking-android-backups.html
#
# header + zlib compressed data
# zlib compressed data contains a POSIX tar file
def unpack_android_backup(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack an Android backup file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    checkfile = open(filename_full, 'rb')

    # skip over the offset
    checkfile.seek(offset+15)
    unpackedsize += 15

    # Then read the version number. Only support version 1 right now.
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'1\n':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported Android backup version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # Then read the compression flag.
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'1\n':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported Android backup version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # Then read the encryption flag. Only "none" is supported,
    # so read 5 bytes (including newline)
    checkbytes = checkfile.read(5)
    if len(checkbytes) != 5:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'none\n':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'decryption not supported'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 5

    # create a temporary file to write the results to
    # then create a zlib decompression object
    tempbackupfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
    decompressobj = zlib.decompressobj()

    # read 1 MB chunks
    chunksize = 1024*1024
    checkbytes = checkfile.read(chunksize)
    try:
        while checkbytes != b'':
            # uncompress the data, and write to an output file
            os.write(tempbackupfile[0], decompressobj.decompress(checkbytes))
            unpackedsize += len(checkbytes) - len(decompressobj.unused_data)
            if len(decompressobj.unused_data) != 0:
                break
            checkbytes = checkfile.read(chunksize)
    except Exception as ex:
        os.fdopen(tempbackupfile[0]).close()
        os.unlink(tempbackupfile[1])
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid compression'}
        return {'status': False, 'error': unpackingerror}
    os.fdopen(tempbackupfile[0]).close()
    checkfile.close()

    tarfilesize = os.stat(tempbackupfile[1]).st_size

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # now unpack the tar ball
    # fr = FileResult( ??? )
    # TODO: fix this: source file not in unpackdir
    tarresult = bangunpack.unpack_tar(pathlib.Path(tempbackupfile[1]), scanenvironment, 0, unpackdir)

    # cleanup
    os.unlink(tempbackupfile[1])
    if not tarresult['status']:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'corrupt tar inside Android backup file'}
        return {'status': False, 'error': unpackingerror}
    if not tarfilesize == tarresult['length']:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'corrupt tar inside Android backup file'}
        return {'status': False, 'error': unpackingerror}

    # add the labels and pass on the results from the tar unpacking
    labels.append('androidbackup')
    labels.append('android')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': tarresult['filesandlabels']}

unpack_android_backup.signatures = {'android_backup': b'ANDROID BACKUP\n'}


# Android resources files (such as "resources.arsc") as found in
# many APK files. Description:
#
# https://android.googlesource.com/platform/frameworks/base.git/+/master/libs/androidfw/include/androidfw/ResourceTypes.h
#
# As the pointer is to the master Git repository line references
# might chance over time.
#
# Around line 182 the format description starts.
def unpack_android_resource(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve an Android resources file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    byteorder = 'little'
    dataunpacked = False
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # first check the kind of file. There are four types of
    # top level files.
    # * NULL type (0x0000)
    # * string type (0x0001)
    # * table type (resources.asrc typically is a table) (0x0002)
    # * XML (Android's "binary XML") (0x0003)
    # In ResourceTypes.h this part is the resChunk_header
    # Only the table type is currently supported.
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}
    resourcetype = int.from_bytes(checkbytes, byteorder=byteorder)
    if resourcetype > 3:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported resource type'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # then the chunk header size
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}
    headersize = int.from_bytes(checkbytes, byteorder=byteorder)
    if offset + headersize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'header size larger than file size'}
        return {'status': False, 'error': unpackingerror}

    # first header is minimally 8 bytes
    if headersize < 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong header size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # then the total chunk size
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}
    totalchunksize = int.from_bytes(checkbytes, byteorder=byteorder)
    if offset + totalchunksize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'chunk size larger than file size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # For unknown reasons many of the files do not seem
    # to use the header size defined in the header.
    #if checkfile.tell() - offset < headersize:
    #    checkfile.seek(offset + headersize)
    #unpackedsize = headersize

    stringtable = {}

    # then each individual chunk, depending on the type
    if resourcetype == 2:
        # It is a table type, so
        # ResourceType.h around line 826:
        # first a package count followed by a stringpool and
        # table package chunks (around line 842)
        # first the amount of ResTable_package structures
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table header'}
            return {'status': False, 'error': unpackingerror}
        restablecount = int.from_bytes(checkbytes, byteorder=byteorder)
        unpackedsize += 4

        # first store the old offset, as it is important to determine
        # the start of the string table and style offsets.
        oldoffset = checkfile.tell()

        stringres = android_resource_string_pool(checkfile, byteorder, offset, oldoffset, filesize)
        if not stringres['status']:
            checkfile.close()
            return stringres

        # skip over the entire chunk
        checkfile.seek(oldoffset + stringres['stringpoolheaderchunksize'])
        unpackedsize = checkfile.tell() - offset

        for i in range(0, restablecount):
            # first store the old offset, as it is important to
            # determine the start of the chunk.
            oldoffset = checkfile.tell()

            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data'}
                return {'status': False, 'error': unpackingerror}
            packageresourcetype = int.from_bytes(checkbytes, byteorder=byteorder)

            # package chunk types (around line 230)
            if packageresourcetype > 515 and packageresourcetype < 512:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'unsupported resource type'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            # then the chunk header size
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data'}
                return {'status': False, 'error': unpackingerror}
            packageheadersize = int.from_bytes(checkbytes, byteorder=byteorder)
            if offset + packageheadersize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'header size larger than file size'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            # then the package chunk size
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data'}
                return {'status': False, 'error': unpackingerror}

            # sanity check: package chunk cannot be outside of the file
            packagesize = int.from_bytes(checkbytes, byteorder=byteorder)
            if oldoffset + packagesize > filesize:
                checkfile.close()
                unpackingerror = {'offset': oldoffset, 'fatal': False,
                                  'reason': 'package chunk cannot be outside file'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4

            # skip over the entire chunk
            checkfile.seek(oldoffset + packagesize)
            unpackedsize = checkfile.tell() - offset
        dataunpacked = True
    elif resourcetype == 3:
        # http://web.archive.org/web/20140916071519/http://justanapplication.wordpress.com/2011/09/22/android-internals-binary-xml-part-two-the-xml-chunk/
        if checkfile.tell() + 8 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'Not enough data for string pool'}
            return {'status': False, 'error': unpackingerror}

        # first a StringPool
        # store the old offset, as it is important to determine
        # the start of the string table and style offsets.
        oldoffset = checkfile.tell()

        stringres = android_resource_string_pool(checkfile, byteorder, offset, oldoffset, filesize)
        if not stringres['status']:
            checkfile.close()
            return stringres

        # skip over the entire chunk
        checkfile.seek(oldoffset + stringres['stringpoolheaderchunksize'])
        unpackedsize = checkfile.tell() - offset

        # store the old offset
        oldoffset = checkfile.tell()

        # then an optional xml resource map and mandatory start namespace,
        # at least 8 bytes
        if checkfile.tell() + 8 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'Not enough data for string pool'}
            return {'status': False, 'error': unpackingerror}

        checkbytes = checkfile.read(2)
        xmlresourcetype = int.from_bytes(checkbytes, byteorder=byteorder)
        if xmlresourcetype == 0x180:
            # header size
            checkbytes = checkfile.read(2)
            chunkheadersize = int.from_bytes(checkbytes, byteorder=byteorder)

            # chunk size
            checkbytes = checkfile.read(2)
            chunksize = int.from_bytes(checkbytes, byteorder=byteorder)

            # sanity checks
            if oldoffset + chunksize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'Not enough data for XML resource map'}
                return {'status': False, 'error': unpackingerror}

            # and skip the chunk
            checkfile.seek(oldoffset + chunksize)

            # and continue reading the start namespace element
            if checkfile.tell() + 8 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'Not enough data for string pool'}
                return {'status': False, 'error': unpackingerror}
            checkbytes = checkfile.read(2)
            xmlresourcetype = int.from_bytes(checkbytes, byteorder=byteorder)

        # followed by a start namespace element or start element
        # record if the first element is a name space element
        first_is_namespace = False
        if xmlresourcetype == 0x100:
            first_is_namespace = True

        if not first_is_namespace and xmlresourcetype != 0x102:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'start namespace or start element not found'}
            return {'status': False, 'error': unpackingerror}

        # go back 2 bytes
        checkfile.seek(-2, os.SEEK_CUR)

        # and process elements until the end of the file
        namespaces = 0
        elementcount = 0
        while True:
            # store the old offset
            oldoffset = checkfile.tell()

            if checkfile.tell() + 8 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'Not enough data for XML element'}
                return {'status': False, 'error': unpackingerror}

            checkbytes = checkfile.read(2)
            xmlresourcetype = int.from_bytes(checkbytes, byteorder=byteorder)

            checkbytes = checkfile.read(2)
            chunkheadersize = int.from_bytes(checkbytes, byteorder=byteorder)

            # chunk size
            checkbytes = checkfile.read(2)
            chunksize = int.from_bytes(checkbytes, byteorder=byteorder)

            # sanity checks
            if chunksize == 0:
                break
            if oldoffset + chunksize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'Not enough data for XML resource map'}
                return {'status': False, 'error': unpackingerror}

            # and skip the chunk
            checkfile.seek(oldoffset + chunksize)

            if xmlresourcetype == 0x100:
                namespaces += 1
            elif xmlresourcetype == 0x101:
                namespaces -= 1
                if namespaces == 0 and first_is_namespace:
                    dataunpacked = True
                    break
            elif xmlresourcetype == 0x102:
                elementcount += 1
            elif xmlresourcetype == 0x103:
                elementcount -= 1
                if elementcount == 0 and not first_is_namespace:
                    dataunpacked = True
                    break
        unpackedsize = checkfile.tell() - offset
    else:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot process chunk with resource type %d' % resourcetype}
        return {'status': False, 'error': unpackingerror}

    if not dataunpacked:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no data could be unpacked'}
        return {'status': False, 'error': unpackingerror}

    # see if the whole file is the android resource file
    if offset == 0 and totalchunksize == filesize:
        checkfile.close()
        labels.append('resource')
        labels.append('android')
        if resourcetype == 3:
            labels.append('binary xml')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file
    if resourcetype == 3:
        outfile_rel = os.path.join(unpackdir, "unpacked-from-binary.xml")
    else:
        outfile_rel = os.path.join(unpackdir, "unpacked-from-resources.arsc")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    if resourcetype == 3:
        unpackedfilesandlabels.append((outfile_rel, ['resource', 'binary xml', 'android resource', 'unpacked']))
    else:
        unpackedfilesandlabels.append((outfile_rel, ['resource', 'android resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_android_resource.extensions = ['resources.arsc']
unpack_android_resource.signatures = {'android_binary_xml': b'\x03\x00\x08\x00'}
unpack_android_resource.pretty = 'androidresource'


# helper function to process String pools in Android resource
# files, binary XML, etc.
#
# references to line numbers are for:
# https://android.googlesource.com/platform/frameworks/base.git/+/master/libs/androidfw/include/androidfw/ResourceTypes.h
def android_resource_string_pool(checkfile, byteorder, offset, oldoffset, filesize):
    '''Helper function to parse Android resource String pool objects'''
    stringtable = {}
    unpackedsize = 0

    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # check if it is indeed a string pool resource (around line 214)
    stringpoolresourcetype = int.from_bytes(checkbytes, byteorder=byteorder)
    if stringpoolresourcetype != 1:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'unsupported string pool resource type'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # then the string pool header size
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    stringpoolheadersize = int.from_bytes(checkbytes, byteorder=byteorder)
    if offset + stringpoolheadersize > filesize:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'header size larger than file size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for table header'}
        return {'status': False, 'error': unpackingerror}

    stringpoolheaderchunksize = int.from_bytes(checkbytes, byteorder=byteorder)
    if offset + stringpoolheaderchunksize > filesize:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'chunk size larger than file size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # followed by the string count
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for table header'}
        return {'status': False, 'error': unpackingerror}
    stringcount = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # followed by the style count
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for table header'}
        return {'status': False, 'error': unpackingerror}
    stylecount = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # then string flags
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for table header'}
        return {'status': False, 'error': unpackingerror}
    stringflags = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # check if everything is UTF-8 or UTF-16 (around line 451)
    isutf16 = True
    if(stringflags & 1 << 8) == 256:
        isutf16 = False

    # then the offset for the string data
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for table header'}
        return {'status': False, 'error': unpackingerror}
    stringoffset = int.from_bytes(checkbytes, byteorder=byteorder)

    if oldoffset + stringoffset > filesize:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for string table'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # and the offset for the style data
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for table header'}
        return {'status': False, 'error': unpackingerror}
    styleoffset = int.from_bytes(checkbytes, byteorder=byteorder)

    if oldoffset + styleoffset > filesize:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for style data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    for s in range(1, stringcount+1):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for string table'}
            return {'status': False, 'error': unpackingerror}
        stringindex = int.from_bytes(checkbytes, byteorder=byteorder)

        # store the current offset
        curoffset = checkfile.tell()
        if oldoffset + stringoffset + stringindex > filesize:
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'string data cannotbe outside of file'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(oldoffset + stringoffset + stringindex)

        # now extract the string and store it
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            unpackingerror = {'offset': oldoffset+stringoffset+stringindex,
                              'fatal': False,
                              'reason': 'not enough data for string data'}
            return {'status': False, 'error': unpackingerror}

        # the length of the string is put in front of the actual
        # string. Decoding of the length depends on whether or not
        # the string table is in UTF-8 or in UTF-16 (see comments
        # in ResourceTypes.cpp, as the header file is missing some
        # information).
        if isutf16:
            strlen = int.from_bytes(checkbytes, byteorder=byteorder)
            if strlen & 0x8000 == 0x8000:
                checkbytes = checkfile.read(2)
                strlen = ((strlen & 0x7fff) << 16) + struct.unpack('<H', checkbytes)[0]
        else:
            strlen = int.from_bytes(checkbytes, byteorder=byteorder)
            if strlen & 0x80 == 0x80:
                # the correct length is actually in the
                # next two bytes for reasons unknown
                checkbytes = checkfile.read(2)
                strlen = ((checkbytes[0] & 0x7f) << 8) + checkbytes[1]
            else:
                # the correct length is actually in the
                # second byte for reasons unknown
                strlen = checkbytes[1]

        strentry = checkfile.read(strlen)
        if len(strentry) != strlen:
            unpackingerror = {'offset': oldoffset+stringoffset+stringindex,
                              'fatal': False,
                              'reason': 'not enough data for string data'}
            return {'status': False, 'error': unpackingerror}
        if not isutf16:
            try:
                # try to decode the string to UTF-8
                stringtable[s] = strentry.decode()
            except UnicodeDecodeError:
                stringtable[s] = strentry
        else:
            stringtable[s] = strentry
        checkfile.seek(curoffset)

    return {'status': True, 'length': unpackedsize,
            'stringtable': stringtable, 'styleoffset': styleoffset,
            'stringpoolheaderchunksize': stringpoolheaderchunksize}


# Android bootloader
#
# https://android.googlesource.com/platform/system/core.git/+/refs/heads/pie-platform-release/mkbootimg/include/bootimg/bootimg.h
#
# There is also a variant based on Little Kernel that uses a slightly
# different header format:
#
# https://github.com/M1cha/android_bootable_bootloader_lk/blob/condor/app/aboot/bootimg.h
def unpack_android_boot_img(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack Android bootloader images'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # the android boot loader images don't have names recorded
    # for the different parts, so just hardcode these.
    kernelname = 'kernel'
    ramdiskname = 'ramdisk'
    secondstagename = 'secondstageloader'
    dtbname = 'dtb'

    # version 0 header is 48 bytes, other headers more
    if offset + 48 > filesize:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    # kernel size
    checkbytes = checkfile.read(4)
    kernelsize = int.from_bytes(checkbytes, byteorder='little')
    if kernelsize == 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'kernel cannot be empty'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # kernel load address, currently not interesting
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # ramdisk size. Officially this should not be 0, but there
    # are images where the ramdisk actually is 0, but then it
    # likely is a variant format.
    checkbytes = checkfile.read(4)
    ramdisksize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # ramdisk load address, currently not interesting
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # second stage bootloader size
    checkbytes = checkfile.read(4)
    secondsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # second stage bootloader load address, currently not interesting
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # tag address, currently not interesting
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # page size, use for sanity checks
    checkbytes = checkfile.read(4)
    pagesize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    is_dtb = False

    # header version, only 0, 1 and 2 have been defined so far
    # There is also a version for Little Kernel that stores a dtb
    # instead and instead of the header version there is a dtb size
    checkbytes = checkfile.read(4)
    headerversion = int.from_bytes(checkbytes, byteorder='little')
    if headerversion > 2:
        # check if the header version is at least 40 (minimum size of dtb)
        if headerversion >= 40:
            is_dtb = True
            dtbsize = headerversion
        else:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unknown boot image header version'}
            return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    if not is_dtb:
        # sanity check for ramdisk size
        if ramdisksize == 0:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'ramdisk cannot be empty'}
            return {'status': False, 'error': unpackingerror}

        # os version, skip for now
        checkbytes = checkfile.read(4)
        os_version = int.from_bytes(checkbytes, byteorder='little')
    else:
        # unused, skip
        checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # boot name (default: 16 bytes)
    checkbytes = checkfile.read(16)
    try:
        bootname = checkbytes.split(b'\x00', 1)[0].decode()
    except UnicodeError:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid boot name'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 16

    # boot args (default: 512 bytes)
    checkbytes = checkfile.read(512)
    try:
        bootargs = checkbytes.split(b'\x00', 1)[0].decode()
    except UnicodeError:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid boot args'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 512

    # various other identifiers, skip for now
    checkfile.seek(32, os.SEEK_CUR)
    unpackedsize += 32

    # some but not all variants have extra boot args
    if not is_dtb:
        # boot extra args (default: 1024 bytes)
        checkbytes = checkfile.read(1024)
        try:
            bootextraargs = checkbytes.split(b'\x00', 1)[0].decode()
        except UnicodeError:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid boot extra args'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1024

    # now extra data for version 1 and version 2, wait for
    # test files first to verify.
    if headerversion != 0 and not is_dtb:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'currently unsupported header version'}
        return {'status': False, 'error': unpackingerror}

    # extra sanity check: the header is one page
    if unpackedsize > pagesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid page size'}
        return {'status': False, 'error': unpackingerror}

    # skip the rest of the header
    checkfile.seek(offset + pagesize)
    unpackedsize = pagesize

    # sanity check: need enough data
    if checkfile.tell() + kernelsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for kernel'}
        return {'status': False, 'error': unpackingerror}

    # write the kernel data
    outfile_rel = os.path.join(unpackdir, kernelname)
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), kernelsize)
    outfile.close()
    checkfile.seek(kernelsize, os.SEEK_CUR)
    unpackedfilesandlabels.append((outfile_rel, []))
    unpackedsize += kernelsize

    # padding
    if kernelsize % pagesize != 0:
        paddingneeded = pagesize - (kernelsize % pagesize)
        checkfile.seek(paddingneeded, os.SEEK_CUR)
        unpackedsize += paddingneeded

    # write the ramdisk
    if ramdisksize != 0:
        # sanity check: need enough data
        if checkfile.tell() + ramdisksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for ramdisk'}
            return {'status': False, 'error': unpackingerror}

        outfile_rel = os.path.join(unpackdir, ramdiskname)
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), ramdisksize)
        outfile.close()
        checkfile.seek(ramdisksize, os.SEEK_CUR)
        unpackedfilesandlabels.append((outfile_rel, []))
        unpackedsize += ramdisksize

        if ramdisksize % pagesize != 0:
            paddingneeded = pagesize - (ramdisksize % pagesize)
            checkfile.seek(paddingneeded, os.SEEK_CUR)
            unpackedsize += paddingneeded

    if secondsize != 0:
        # sanity check: need enough data
        if checkfile.tell() + secondsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for second stage bootloader'}
            return {'status': False, 'error': unpackingerror}

        # write the second stage bootloader
        outfile_rel = os.path.join(unpackdir, secondstagename)
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), secondsize)
        outfile.close()
        checkfile.seek(secondsize, os.SEEK_CUR)
        unpackedfilesandlabels.append((outfile_rel, ["bootloader"]))
        unpackedsize += secondsize

        if secondsize % pagesize != 0:
            paddingneeded = pagesize - (secondsize % pagesize)
            checkfile.seek(paddingneeded, os.SEEK_CUR)
            unpackedsize += paddingneeded

    if is_dtb:
        # sanity check: need enough data
        if checkfile.tell() + dtbsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for dtb data'}
            return {'status': False, 'error': unpackingerror}

        # write the dtb data
        outfile_rel = os.path.join(unpackdir, dtbname)
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), dtbsize)
        outfile.close()
        checkfile.seek(secondsize, os.SEEK_CUR)
        unpackedfilesandlabels.append((outfile_rel, ["dtb"]))
        unpackedsize += dtbsize

        if dtbsize % pagesize != 0:
            paddingneeded = pagesize - (dtbsize % pagesize)
            checkfile.seek(paddingneeded, os.SEEK_CUR)
            unpackedsize += paddingneeded

    if offset == 0 and unpackedsize == filesize:
        labels.append("android")
        labels.append("android boot image")
        #if is_dtb:
            # would this label be correct? TODO
            #labels.append("little kernel")

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_android_boot_img.signatures = {'androidbootimg': b'ANDROID!'}
unpack_android_boot_img.minimum_size = 48
