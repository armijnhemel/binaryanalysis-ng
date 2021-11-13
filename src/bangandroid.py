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

'''Built in carvers/verifiers/unpackers for various Android formats (except
certain formats such as APK, which are with other unpackers).'''

import os
import tempfile
import zlib
import re
import pathlib
import brotli

# own modules
import bangunpack


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
