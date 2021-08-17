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


# Android Dalvik
#
# https://source.android.com/devices/tech/dalvik/dex-format
#
# Internet archive link:
#
# http://web.archive.org/web/20180520110013/https://source.android.com/devices/tech/dalvik/dex-format
#
# (sections "File layout" and "Items and related structures")
def unpack_dex(
        fileresult, scanenvironment, offset, unpackdir,
        dryrun=False,
        verifychecksum=True):
    '''Verify and/or carve an Android Dex file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    dexresult = {}

    if filesize - offset < 70:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip over the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then the version. In the specification it is part of
    # DEX_FILE_MAGIC, but check it separately here to filter
    # any false positives.

    # dex versions defined in:
    # https://android.googlesource.com/platform/dalvik/+/master/tools/dexdeps/src/com/android/dexdeps/DexData.java

    dexversions = [b'035\x00', b'037\x00', b'038\x00', b'039\x00']

    checkbytes = checkfile.read(4)
    if checkbytes not in dexversions:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong Dex version'}
        return {'status': False, 'error': unpackingerror}
    dexversion = checkbytes[:3].decode()
    unpackedsize += 4

    dexresult['version'] = dexversion

    # first check if the file is little endian. The endianness
    # bytes can be found at offset 40
    oldoffset = checkfile.tell()
    checkfile.seek(offset+40)
    checkbytes = checkfile.read(4)

    if int.from_bytes(checkbytes, byteorder='little') != 0x12345678:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'incorrect endianness bytes'}
        return {'status': False, 'error': unpackingerror}

    # return to the old offset
    checkfile.seek(oldoffset)

    # then the adler checksum
    checkbytes = checkfile.read(4)
    adlerchecksum = int.from_bytes(checkbytes, byteorder='little')

    # then the signature
    signature = checkfile.read(20)

    # then the file size
    checkbytes = checkfile.read(4)
    dexsize = int.from_bytes(checkbytes, byteorder='little')
    if offset + dexsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'declared size bigger than file'}
        return {'status': False, 'error': unpackingerror}

    # header size
    checkbytes = checkfile.read(4)
    headersize = int.from_bytes(checkbytes, byteorder='little')
    if headersize != 0x70:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong header size'}
        return {'status': False, 'error': unpackingerror}

    # skip the endianness bit
    checkfile.seek(4, os.SEEK_CUR)

    # link size
    checkbytes = checkfile.read(4)
    linksize = int.from_bytes(checkbytes, byteorder='little')

    # link offset
    checkbytes = checkfile.read(4)
    linkoffset = int.from_bytes(checkbytes, byteorder='little')

    if linkoffset != 0:
        if offset + linkoffset + linksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'link section outside of file'}
            return {'status': False, 'error': unpackingerror}

    # map item offset, "must be non-zero"
    checkbytes = checkfile.read(4)
    mapoffset = int.from_bytes(checkbytes, byteorder='little')
    if mapoffset == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'map item must be non-zero'}
        return {'status': False, 'error': unpackingerror}
    if offset + mapoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'map item outside of file'}
        return {'status': False, 'error': unpackingerror}

    # string ids size
    checkbytes = checkfile.read(4)
    stringidssize = int.from_bytes(checkbytes, byteorder='little')

    # string ids offset
    checkbytes = checkfile.read(4)
    stringidsoffset = int.from_bytes(checkbytes, byteorder='little')

    if stringidsoffset != 0:
        if stringidsoffset < headersize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'strings section cannot be inside header'}
            return {'status': False, 'error': unpackingerror}
        if offset + stringidsoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'strings section outside of file'}
            return {'status': False, 'error': unpackingerror}
    else:
        # "0 if string_ids_size == 0"
        if stringidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'strings section/strings size mismatch'}
            return {'status': False, 'error': unpackingerror}

    # type_ids_size, "at most 65535"
    checkbytes = checkfile.read(4)
    typeidssize = int.from_bytes(checkbytes, byteorder='little')
    if typeidssize > 65535:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'too many type identifiers'}
        return {'status': False, 'error': unpackingerror}

    # type ids offset
    checkbytes = checkfile.read(4)
    typeidsoffset = int.from_bytes(checkbytes, byteorder='little')

    if typeidsoffset != 0:
        if typeidsoffset < headersize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'type section cannot be inside header'}
            return {'status': False, 'error': unpackingerror}
        if offset + typeidsoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'type section outside of file'}
            return {'status': False, 'error': unpackingerror}
    else:
        # "0 if type_ids_size == 0"
        if typeidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'type section/type size mismatch'}
            return {'status': False, 'error': unpackingerror}

    # proto ids size, "at most 65535"
    checkbytes = checkfile.read(4)
    protoidssize = int.from_bytes(checkbytes, byteorder='little')
    if protoidssize > 65535:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'too many type identifiers'}
        return {'status': False, 'error': unpackingerror}

    # proto ids offset
    checkbytes = checkfile.read(4)
    protoidsoffset = int.from_bytes(checkbytes, byteorder='little')

    if protoidsoffset != 0:
        if protoidsoffset < headersize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype section cannot be inside header'}
            return {'status': False, 'error': unpackingerror}
        if offset + protoidsoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype section outside of file'}
            return {'status': False, 'error': unpackingerror}
    else:
        # "0 if proto_ids_size == 0"
        if protoidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype section/prototype size mismatch'}
            return {'status': False, 'error': unpackingerror}

    # fields ids size
    checkbytes = checkfile.read(4)
    fieldsidssize = int.from_bytes(checkbytes, byteorder='little')

    # fields ids offset
    checkbytes = checkfile.read(4)
    fieldsidsoffset = int.from_bytes(checkbytes, byteorder='little')

    if fieldsidsoffset != 0:
        if fieldsidsoffset < headersize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'fields section cannot be inside header'}
            return {'status': False, 'error': unpackingerror}
        if offset + fieldsidsoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'fields section outside of file'}
            return {'status': False, 'error': unpackingerror}
    else:
        # "0 if field_ids_size == 0"
        if fieldsidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'fields section/fields size mismatch'}
            return {'status': False, 'error': unpackingerror}

    # method ids size
    checkbytes = checkfile.read(4)
    methodidssize = int.from_bytes(checkbytes, byteorder='little')

    # method ids offset
    checkbytes = checkfile.read(4)
    methodidsoffset = int.from_bytes(checkbytes, byteorder='little')

    if methodidsoffset != 0:
        if methodidsoffset < headersize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'methods section cannot be inside header'}
            return {'status': False, 'error': unpackingerror}
        if offset + methodidsoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'methods section outside of file'}
            return {'status': False, 'error': unpackingerror}
    else:
        # "0 if method_ids_size == 0"
        if methodidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'methods section/methods size mismatch'}
            return {'status': False, 'error': unpackingerror}

    # class definitions size
    checkbytes = checkfile.read(4)
    classdefssize = int.from_bytes(checkbytes, byteorder='little')

    # class definitions offset
    checkbytes = checkfile.read(4)
    classdefsoffset = int.from_bytes(checkbytes, byteorder='little')

    if classdefsoffset != 0:
        if classdefsoffset < headersize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'class definitions cannot be inside header'}
            return {'status': False, 'error': unpackingerror}
        if offset + classdefsoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'class definitions outside of file'}
            return {'status': False, 'error': unpackingerror}
    else:
        # "0 if class_defs_size == 0"
        if classdefssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'class definitions section/class definitions size mismatch'}
            return {'status': False, 'error': unpackingerror}

    # data size, "Must be an even multiple of sizeof(uint)"
    # according to the docs but this seems to be completely
    # ignored by Google.
    checkbytes = checkfile.read(4)
    datasize = int.from_bytes(checkbytes, byteorder='little')

    # data offset
    checkbytes = checkfile.read(4)
    dataoffset = int.from_bytes(checkbytes, byteorder='little')

    if offset + dataoffset + datasize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data outside of file'}
        return {'status': False, 'error': unpackingerror}


    # store the Adler32 of the uncompressed data
    dexadler = zlib.adler32(b'')

    # jump to byte 12
    checkfile.seek(offset+12)

    # the first 20 bytes are only relevant for the Adler32
    checkbytes = checkfile.read(20)
    dexadler = zlib.adler32(checkbytes, dexadler)

    if verifychecksum:
        dexsha1 = hashlib.new('sha1')

    # read all data to check the Adler32 checksum and the SHA1 checksum
    bytes_to_read = dexsize - 12 - 20
    readsize = 10000000
    while bytes_to_read > 0:
        if readsize > bytes_to_read:
            readsize = bytes_to_read
        checkbytes = checkfile.read(readsize)
        if checkbytes == b'':
            break
        dexadler = zlib.adler32(checkbytes, dexadler)
        if verifychecksum:
            dexsha1.update(checkbytes)
        bytes_to_read -= len(checkbytes)

    if dexadler != adlerchecksum:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong Adler32'}
        return {'status': False, 'error': unpackingerror}

    if verifychecksum:
        # this happens quite a lot, also with Dex files coming
        # from Google. Treat this as a non-fatal warning if configured.
        strict_sha1 = False
        if dexsha1.digest() != signature:
            if strict_sha1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'wrong SHA1'}
                return {'status': False, 'error': unpackingerror}
            else:
                labels.append('wrong SHA-1')

    # There are two ways to access the data: the first is to use the
    # so called "map list" (the easiest). The second is to walk all the
    # items separately.
    # In this implementation the map list is primarily used, with the
    # other data used for additional sanity checks.

    # jump to the offset of the string identifiers list
    checkfile.seek(offset + stringidsoffset)

    # keep track of the string identifiers
    stringids = {}

    # keep track of the type identifiers
    typeids = {}

    # some regex for sanity checks
    reshorty = re.compile('(?:V|[ZBSCIJFDL])[ZBSCIJFDL]*$')

    # read each string_id_item, which is an offset into the data section
    for i in range(0, stringidssize):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for string identifier offset'}
            return {'status': False, 'error': unpackingerror}
        string_data_offset = int.from_bytes(checkbytes, byteorder='little')
        if offset + string_data_offset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'string identifier offset outside file'}
            return {'status': False, 'error': unpackingerror}
        if string_data_offset < dataoffset:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'string identifier offset not in data section'}
            return {'status': False, 'error': unpackingerror}

        # store the old offset
        oldoffset = checkfile.tell()

        # then jump to the new offset
        checkfile.seek(offset + string_data_offset)

        # The first few bytes will be the size in
        # ULEB128 encoding:
        #
        # https://en.wikipedia.org/wiki/LEB128
        stringiddata = b''
        while True:
            checkbytes = checkfile.read(1)
            if checkbytes == b'\x00':
                break
            stringiddata += checkbytes
        for s in enumerate(stringiddata):
            if s[1] & 0x80 == 0x80:
                continue

            # The string data itself is in Modified UTF-8 encoding.
            # https://en.wikipedia.org/wiki/UTF-8#Modified_UTF-8
            stringid = stringiddata[s[0]+1:].replace(b'\xc0\x80', b'\x00')

            # several characters have been replaced as well (surrogate)
            # TODO

            try:
                stringid = stringid.decode()
            except UnicodeDecodeError:
                if b'\xed' not in stringid:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid MUTF-8'}
                    return {'status': False, 'error': unpackingerror}
            stringids[i] = stringid
            break

        # and return to the old offset
        checkfile.seek(oldoffset)

    # jump to the offset of the string identifiers list
    checkfile.seek(offset + typeidsoffset)

    # read each type_id_item. These have to be valid ids in the
    # string identifier table
    for i in range(0, typeidssize):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for string identifier offset'}
            return {'status': False, 'error': unpackingerror}
        descriptor_idx = int.from_bytes(checkbytes, byteorder='little')

        if descriptor_idx not in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'type identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}
        typeids[i] = stringids[descriptor_idx]

    # jump to the offset of the prototype identifiers list
    checkfile.seek(offset + protoidsoffset)

    # read each proto_id_item
    for i in range(0, protoidssize):
        # first an index into the string identifiers list
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for prototype identifier offset'}
            return {'status': False, 'error': unpackingerror}
        shorty_idx = int.from_bytes(checkbytes, byteorder='little')

        if shorty_idx not in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}

        # the shorty index points to a string that must conform
        # to ShortyDescription syntax (see specifications)
        if reshorty.match(stringids[shorty_idx]) is None:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid prototype identifier'}
            return {'status': False, 'error': unpackingerror}

        # then the return type index, which has to be a valid
        # index into the type ids list
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for prototype return identifier offset'}
            return {'status': False, 'error': unpackingerror}
        return_type_idx = int.from_bytes(checkbytes, byteorder='little')

        if return_type_idx not in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype return type not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        # finally the parameters offset. This can either by 0 or
        # a valid offset into the data section.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for prototype parameters offset'}
            return {'status': False, 'error': unpackingerror}
        parameters_off = int.from_bytes(checkbytes, byteorder='little')
        if offset + parameters_off > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype parameters offset outside file'}
            return {'status': False, 'error': unpackingerror}
        if parameters_off != 0:
            if parameters_off < dataoffset:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'prototype parameters offset not in data section'}
                return {'status': False, 'error': unpackingerror}

    # jump to the offset of the field identifiers list
    checkfile.seek(offset + fieldsidsoffset)

    # read each field_id_item
    for i in range(0, fieldsidssize):
        # first an index into the string identifiers list
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        class_idx = int.from_bytes(checkbytes, byteorder='little')

        if class_idx not in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        # "must be a class type"
        if not typeids[class_idx].startswith('L'):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier does not point to a class'}
            return {'status': False, 'error': unpackingerror}

        # type_idx
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        type_idx = int.from_bytes(checkbytes, byteorder='little')

        if type_idx not in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        # name_idx
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        name_idx = int.from_bytes(checkbytes, byteorder='little')

        if name_idx not in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}

    # jump to the offset of the method identifiers list
    checkfile.seek(offset + methodidsoffset)

    # read each method_id_item
    for i in range(0, methodidssize):
        # first an index into the string identifiers list
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        class_idx = int.from_bytes(checkbytes, byteorder='little')

        if class_idx not in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'method identifier not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        # "must be a class type or array type"
        if not (typeids[class_idx].startswith('L') or typeids[class_idx].startswith('[')):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'method identifier does not point to a class'}
            return {'status': False, 'error': unpackingerror}

        # proto_idx
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        proto_idx = int.from_bytes(checkbytes, byteorder='little')

        # TODO: has to be a valid entry into the prototype list

        # name_idx
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        name_idx = int.from_bytes(checkbytes, byteorder='little')

        if name_idx not in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}

    # Done with most of the sanity checks, so now use
    # the map item instead, as it is more convenient.

    # there is just a limited set of valid map item types
    validmapitems = set([0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
                         0x0006, 0x0007, 0x0008, 0x1000, 0x1001, 0x1002,
                         0x1003, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
                         0x2005, 0x2006])

    # map offset "should be to an offset in the data section"
    if mapoffset < dataoffset:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'map item not in data section'}
        return {'status': False, 'error': unpackingerror}

    # jump to the offset of the map item
    checkfile.seek(offset + mapoffset)

    # store the types to offsets, plus the amount of map type items
    maptypetooffsets = {}

    seenmaptypes = set()

    # parse map_list
    checkbytes = checkfile.read(4)
    mapsize = int.from_bytes(checkbytes, byteorder='little')
    for i in range(0, mapsize):
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for map type'}
            return {'status': False, 'error': unpackingerror}
        maptype = int.from_bytes(checkbytes, byteorder='little')
        if maptype not in validmapitems:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid map type'}
            return {'status': False, 'error': unpackingerror}

        # map types can appear at most once
        if maptype in seenmaptypes:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'duplicate map type'}
            return {'status': False, 'error': unpackingerror}
        seenmaptypes.add(maptype)

        # unused
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for map item'}
            return {'status': False, 'error': unpackingerror}

        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for map item'}
            return {'status': False, 'error': unpackingerror}
        mapitemsize = int.from_bytes(checkbytes, byteorder='little')

        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for map item offset'}
            return {'status': False, 'error': unpackingerror}
        mapitemoffset = int.from_bytes(checkbytes, byteorder='little')
        if offset + mapitemoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'map item offset outside of file'}
            return {'status': False, 'error': unpackingerror}
        maptypetooffsets[maptype] = (mapitemoffset, mapitemsize)

    unpackedsize = dataoffset + datasize
    if offset == 0 and unpackedsize == filesize:
        labels.append('dex')
        labels.append('android')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    if not dryrun:
        # else carve the file
        outfile_rel = os.path.join(unpackdir, "classes.dex")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, ['dex', 'android', 'unpacked']))

    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_dex.signatures = {'dex': b'dex\n'}
unpack_dex.minimum_size = 70


# Android Dalvik, optimized
#
# https://android.googlesource.com/platform/dalvik.git/+/master/libdex/DexFile.h
#
# Internet archive link:
#
# http://web.archive.org/web/20180816094438/https://android.googlesource.com/platform/dalvik.git/+/master/libdex/DexFile.h
#
# (struct DexOptHeader and DexFile)
def unpack_odex(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve an Android Odex file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize < 40:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip over the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then the version. So far only one has been released but
    # it could be that more will be released, so make it extensible.
    odexversions = [b'036\x00']

    checkbytes = checkfile.read(4)
    if checkbytes not in odexversions:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong Odex version'}
        return {'status': False, 'error': unpackingerror}
    dexversion = checkbytes[:3].decode()
    unpackedsize += 4

    # file offset to Dex header
    checkbytes = checkfile.read(4)
    dexoffset = int.from_bytes(checkbytes, byteorder='little')

    # dex length
    checkbytes = checkfile.read(4)
    dexlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + dexlength + dexoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Dex file outside of file'}
        return {'status': False, 'error': unpackingerror}

    maxunpack = dexoffset + dexlength

    # dependency table offset
    checkbytes = checkfile.read(4)
    depsoffset = int.from_bytes(checkbytes, byteorder='little')

    # dependency table length
    checkbytes = checkfile.read(4)
    depslength = int.from_bytes(checkbytes, byteorder='little')
    if offset + depslength + depsoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Dependency table outside of file'}
        return {'status': False, 'error': unpackingerror}

    maxunpack = max(maxunpack, depsoffset + depslength)

    # optimized table offset
    checkbytes = checkfile.read(4)
    optoffset = int.from_bytes(checkbytes, byteorder='little')

    # optimized table length
    checkbytes = checkfile.read(4)
    optlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + optlength + optoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Optimized table outside of file'}
        return {'status': False, 'error': unpackingerror}

    maxunpack = max(maxunpack, optoffset + optlength)

    # skip the flags
    checkfile.seek(4, os.SEEK_CUR)

    # Adler32 checksum
    checkbytes = checkfile.read(4)
    adlerchecksum = int.from_bytes(checkbytes, byteorder='little')

    # store the Adler32 of the uncompressed data
    dexadler = zlib.adler32(b'')

    # first the deps
    checkfile.seek(offset+depsoffset)
    checkbytes = checkfile.read(depslength)
    dexadler = zlib.adler32(checkbytes, dexadler)

    # then padding, if any
    if depslength % 8 != 0:
        padding_length = 8 - (depslength % 8)
        checkbytes = checkfile.read(padding_length)
        dexadler = zlib.adler32(checkbytes, dexadler)

    # then the optimized table
    checkfile.seek(offset+optoffset)
    checkbytes = checkfile.read(optlength)
    dexadler = zlib.adler32(checkbytes, dexadler)

    if dexadler != adlerchecksum:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong Adler32'}
        return {'status': False, 'error': unpackingerror}

    # now check to see if it is an valid Dex. It is extremely
    # unlikely at this point that it is an invalid file.
    dryrun = True
    verifychecksum = False
    dexres = unpack_dex(fileresult, scanenvironment, offset + dexoffset,
                        unpackdir, dryrun, verifychecksum)
    if not dexres['status']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid Dex data'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = maxunpack
    if offset == 0 and unpackedsize == filesize:
        labels.append('odex')
        labels.append('android')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file
    outfile_rel = os.path.join(unpackdir, "unpacked.odex")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((outfile_rel, ['dex', 'android', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_odex.signatures = {'odex': b'dey\n'}
unpack_odex.minimum_size = 40


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


# Android tzdata file. These are actually time zone files, with
# some extra metadata.
# The structure is defined in Android's source code, for example:
# https://android.googlesource.com/platform/bionic/+/lollipop-mr1-dev/libc/tools/zoneinfo/ZoneCompactor.java
def unpack_android_tzdata(fileresult, scanenvironment, offset, unpackdir):
    '''Verify Android's tzdata file and unpack data from it'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if offset + 24 > filesize:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not a valid Android tzdata header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the offset
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(8)
    if checkbytes != b'tzdata20':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not a valid Android tzdata header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # the next two bytes have to be integers,
    # followed by a character and then a NUL byte
    checkbytes = checkfile.read(4)
    tzrs = re.match(b"\d{2}\w\x00", checkbytes)
    if tzrs is None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not a valid Android tzdata header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # index_offset
    checkbytes = checkfile.read(4)
    index_offset = int.from_bytes(checkbytes, byteorder='big')
    if offset + index_offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'offset outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # data_offset
    checkbytes = checkfile.read(4)
    data_offset = int.from_bytes(checkbytes, byteorder='big')
    if offset + data_offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'offset outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # zonetab_offset
    checkbytes = checkfile.read(4)
    zonetab_offset = int.from_bytes(checkbytes, byteorder='big')
    if offset + zonetab_offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'offset outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # seek to the index_offset, should be the same as unpackedsize
    if index_offset != unpackedsize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for index_offset'}
        return {'status': False, 'error': unpackingerror}

    maxoffset = unpackedsize
    dataunpacked = False
    tzcounter = 0

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # read all the fonts, until either the data_offset or zonetab_offset
    while True:
        if offset + unpackedsize + 52 >= filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for entry'}
            return {'status': False, 'error': unpackingerror}

        # first the zone name
        checkbytes = checkfile.read(40)
        if checkbytes == b'':
            break
        unpackedsize += 40
        try:
            zonename = checkbytes.split(b'\x00', 1)[0].decode()
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid name for timezone'}
            return {'status': False, 'error': unpackingerror}
        if zonename == '':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid name for timezone'}
            return {'status': False, 'error': unpackingerror}

        # then the offset
        checkbytes = checkfile.read(4)
        unpackedsize += 4
        tzoffset = int.from_bytes(checkbytes, byteorder='big')

        # then the length
        checkbytes = checkfile.read(4)
        unpackedsize += 4
        tzlength = int.from_bytes(checkbytes, byteorder='big')

        if offset + tzoffset + tzlength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'timezone data outside of file'}
            return {'status': False, 'error': unpackingerror}

        # then raw gmt offset, ignore
        checkbytes = checkfile.read(4)
        unpackedsize += 4
        if unpackedsize >= data_offset:
            break
        if unpackedsize >= zonetab_offset:
            break

        # first open a target file for writing
        # and create directories first if needed
        outfile_rel = os.path.join(unpackdir, zonename)
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        if '/' in zonename:
            os.makedirs(os.path.dirname(outfile_full), exist_ok=True)

        # open the output file for writing
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset + data_offset + tzoffset, tzlength)
        outfile.close()

        unpackedfilesandlabels.append((outfile_rel, []))

        maxoffset = max(maxoffset, data_offset + tzoffset + tzlength)
        dataunpacked = True
        tzcounter += 1

    if not dataunpacked:
        checkfile.close()
        unpackingerror = {'offset': offset,
                          'fatal': False,
                          'reason': 'no timezone data found'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = maxoffset
    if unpackedsize != zonetab_offset:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for zonetab_offset'}
        return {'status': False, 'error': unpackingerror}

    # now the zone.tab information. Compared to the original file
    # the comments have been stripped, but it is the same otherwise.
    # first write the conntents of the file.
    outfile_rel = os.path.join(unpackdir, 'zone.tab')
    outfile_full = scanenvironment.unpack_path(outfile_rel)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset + zonetab_offset, filesize - maxoffset)
    outfile.close()
    checkfile.close()

    # now reopen the target file read only in text mode. The zone.tab
    # file should have ASCII characters only.
    isopened = False

    # open the new file in text only mode
    try:
        checkfile = open(outfile_full, 'r')
        isopened = True
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not valid zone.tab data'}
        return {'status': False, 'error': unpackingerror}

    linesread = 0
    try:
        for checkline in checkfile:
            linesread += 1
    except:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not valid zone.tab data'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0:
        labels.append('resource')
        labels.append('timezone')
        labels.append('android')

    unpackedsize = filesize - offset

    unpackedfilesandlabels.append((outfile_rel, ['resource']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_android_tzdata.extensions = ['tzdata']
unpack_android_tzdata.pretty = 'tzdata'
unpack_android_tzdata.minimum_size = 24


# Android verfied boot images
# https://android.googlesource.com/platform/external/avb/+/master/avbtool
def unpack_avb(fileresult, scanenvironment, offset, unpackdir):
    '''Label/verify/carve Android verified boot images'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize - offset < 256:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the offset
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # major version
    checkbytes = checkfile.read(4)
    majorversion = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # minor version
    checkbytes = checkfile.read(4)
    minorversion = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # authentication block size
    checkbytes = checkfile.read(8)
    authenticationblocksize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # auxiliary block size
    checkbytes = checkfile.read(8)
    auxiliaryblocksize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # algorithm type
    checkbytes = checkfile.read(4)
    algorithmtype = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # hash offset
    checkbytes = checkfile.read(8)
    hashoffset = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # hash size
    checkbytes = checkfile.read(8)
    hashsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # signature offset
    checkbytes = checkfile.read(8)
    signatureoffset = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # signature size
    checkbytes = checkfile.read(8)
    signaturesize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # public key offset
    checkbytes = checkfile.read(8)
    publickeyoffset = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # public key size
    checkbytes = checkfile.read(8)
    publickeysize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # public key metadata offset
    checkbytes = checkfile.read(8)
    publickeymetadataoffset = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # public key metadata size
    checkbytes = checkfile.read(8)
    publickeymetadatasize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # descriptors offset
    checkbytes = checkfile.read(8)
    descriptorsoffset = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # descriptors size
    checkbytes = checkfile.read(8)
    descriptorssize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # rollback index
    checkbytes = checkfile.read(8)
    rollbackindex = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # flags
    checkbytes = checkfile.read(4)
    flags = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # 4 padding bytes
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    # release string (NUL terminated)
    checkbytes = checkfile.read(48)
    try:
        releasestring = checkbytes.split(b'\x00')[0].decode()
    except UnicodeDecodeError:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid release string'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 48

    # 80 padding bytes
    checkbytes = checkfile.read(80)
    unpackedsize += 80

    authoffset = unpackedsize
    auxoffset = authoffset + authenticationblocksize

    maxoffset = max(auxoffset + authenticationblocksize,
                    authoffset + hashoffset + hashsize,
                    authoffset + signatureoffset + signaturesize,
                    auxoffset + publickeyoffset + publickeysize,
                    auxoffset + descriptorsoffset + descriptorssize)
    unpackedsize = maxoffset
    if offset + unpackedsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset,
                          'fatal': False,
                          'reason': 'data outside of file'}
        return {'status': False, 'error': unpackingerror}

    # block is padded to 4096 in standard Android images
    # but could have been changed. Ignore other sizes for now.
    paddinglength = 4096 - (unpackedsize % 4096)
    if paddinglength != 0:
        checkfile.seek(offset + unpackedsize)
        checkbytes = checkfile.read(paddinglength)
        if checkbytes != b'\x00' * paddinglength:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid value for padding'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += paddinglength

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('android')
        labels.append('android verified boot')

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    extrabytesread = 0
    # it could be that there is also a AVB footer, so keep reading
    while filesize - checkfile.tell() >= 4096:
        checkbytes = checkfile.read(4096)
        if b'AVBf' in checkbytes:
            footerpos = checkbytes.find(b'AVBf')
            if footerpos != 0:
                if checkbytes[:footerpos] != b'\x00' * footerpos:
                    break
            if len(checkbytes) - footerpos < 64:
                break
            majorversion = int.from_bytes(checkbytes[footerpos+4:footerpos+8], byteorder='big')
            minorversion = int.from_bytes(checkbytes[footerpos+8:footerpos+12], byteorder='big')
            originalsize = int.from_bytes(checkbytes[footerpos+12:footerpos+20], byteorder='big')
            vbmetaoffset = int.from_bytes(checkbytes[footerpos+20:footerpos+28], byteorder='big')
            vbmetasize = int.from_bytes(checkbytes[footerpos+28:footerpos+36], byteorder='big')
            if checkbytes[footerpos+36:footerpos+64] != b'\x00' * 28:
                break
            extrabytesread += footerpos + 64

            # vbmetaoffset should correspond with offset
            if checkfile.tell() - unpackedsize - extrabytesread == offset:
                unpackedsize += extrabytesread
            break
        else:
            if checkbytes != b'\x00' * 4096:
                break
        extrabytesread += 4096

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.img")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((outfile_rel, ['android', 'android verified boot', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_avb.signatures = {'avb': b'AVB0'}
unpack_avb.minimum_size = 256


# unpack boot files found on certain Android devices equiped with
# Qualcomm Snapdragon chips.
#
# Example sources:
# https://android.googlesource.com/device/lge/mako/+/master/releasetools.py
#
# Example device: Pixel 2
def unpack_android_boot_msm(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack Android bootloader images (Qualcomm Snapdragon)'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if offset + 20 > filesize:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    # number of images
    checkbytes = checkfile.read(4)
    numimages = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # start offset
    checkbytes = checkfile.read(4)
    startoffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + startoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'data cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # boot loader size
    checkbytes = checkfile.read(4)
    bootloadersize = int.from_bytes(checkbytes, byteorder='little')
    if offset + bootloadersize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'data cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    imginfo = []

    maxsize = startoffset

    if offset + unpackedsize + numimages * (64+4) > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for imginfo array'}
        return {'status': False, 'error': unpackingerror}

    # img info array
    for i in range(0, numimages):
        # name
        checkbytes = checkfile.read(64)
        try:
            imgname = checkbytes.split(b'\x00')[0].decode()
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid partition name'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 64

        # size
        checkbytes = checkfile.read(4)
        imgsize = int.from_bytes(checkbytes, byteorder='little')
        maxsize += imgsize
        if offset + maxsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'image outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # store name and size, check later
        imginfo.append((imgname, imgsize))

    if maxsize != bootloadersize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'size of images and bootloader size do not match'}
        return {'status': False, 'error': unpackingerror}

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    checkfile.seek(offset+startoffset)
    for i in imginfo:
        outfile_rel = os.path.join(unpackdir, i[0])
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), i[1])
        outfile.close()
        checkfile.seek(i[1], os.SEEK_CUR)
        unpackedfilesandlabels.append((outfile_rel, []))
    unpackedsize = bootloadersize

    if offset == 0 and unpackedsize == filesize:
        labels.append("snapdragon")
        labels.append("bootloader")

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_android_boot_msm.signatures = {'androidbootmsm': b'BOOTLDR!'}
unpack_android_boot_msm.minimum_size = 20


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


# unpack update files in nb0 format
#
# There is very little documentation about this format. The
# format was found out by studying this open source licensed
# code:
#
# https://github.com/yohanes/Acer-BeTouch-E130-RUT/blob/master/nb0.c
#
# Test file: "ViewPad 7 Firmware v3_42_uk.zip"
#
# This extension is also often used for Windows CE files
def unpack_nb0(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack Android nb0 update files'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # open the file
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # first four bytes are the number of headers
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for headers'}
        return {'status': False, 'error': unpackingerror}
    amount_of_headers = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # for each of the headers there should be 64 bytes of data
    if offset + 4 + amount_of_headers * 64 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for headers'}
        return {'status': False, 'error': unpackingerror}

    headers = {}
    maxheader = 0
    for header in range(0, amount_of_headers):
        # each header is 64 bytes, consisting of
        # 1. offset (4 bytes)
        # 2. size (4 bytes)
        # 3. unknown (4 bytes)
        # 4. unknown (4 bytes)
        # 5. name (48 bytes, NUL terminated)
        checkbytes = checkfile.read(4)
        headeroffset = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        checkbytes = checkfile.read(4)
        headersize = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        maxheader = max(maxheader, headeroffset + headersize)

        checkfile.seek(8, os.SEEK_CUR)
        unpackedsize += 8

        checkbytes = checkfile.read(48)
        try:
            headername = checkbytes.split(b'\x00', 1)[0].decode()
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid name in header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 48

        headers[header] = {'offset': headeroffset, 'size': headersize,
                           'name': headername}

    if offset + unpackedsize + maxheader > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data outside of file'}
        return {'status': False, 'error': unpackingerror}

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # short sanity check to see if there is enough data
    for header in headers:
        unpackoffset = offset + unpackedsize + headers[header]['offset']
        outfile_rel = os.path.join(unpackdir, headers[header]['name'])
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), unpackoffset, headers[header]['size'])
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, []))

    unpackedsize += maxheader

    if offset == 0 and unpackedsize == filesize:
        labels.append("nb0")

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_nb0.extensions = ['.nb0']
unpack_nb0.pretty = 'nb0'


# DHTB signing header
# https://github.com/osm0sis/dhtbsign
def unpack_dhtb(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack Samsung/Spreadtrum DHTB signing header'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if offset + 512 > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and jump to the offset of the payload size
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset + 48)

    checkbytes = checkfile.read(4)
    payload_size = int.from_bytes(checkbytes, byteorder='little')

    if offset + 512 + payload_size > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for payload'}
        return {'status': False, 'error': unpackingerror}

    # jump back to the start of the sha256 (32 bytes)
    checkfile.seek(offset + 8)
    checkbytes = checkfile.read(32)
    checksum = int.from_bytes(checkbytes, byteorder='little')

    # optionally pad
    padding = 0
    if payload_size % 512 != 0:
        padding = 512 - (payload_size%512)
        checkfile.seek(offset + 512 + payload_size)
        checkbytes = set(checkfile.read(padding))
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid padding bytes'}
            return {'status': False, 'error': unpackingerror}

    unpackedsize = 512 + payload_size + padding
    if offset == 0 and filesize == unpackedsize:
        labels.append('dhtb')
        labels.append('android')
    else:
        # else carve the file
        outfile_rel = os.path.join(unpackdir, "unpacked-from-dhtb")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

            # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, ['dhtb', 'android', 'unpacked']))
    checkfile.close()

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_dhtb.signatures = {'dhtb': b'DHTB\x01\x00\x00'}
unpack_dhtb.minimum_size = 512
