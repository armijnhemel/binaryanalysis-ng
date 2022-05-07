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

import os
import collections
import math

# NOTE: this file is no longer being used. The code below is just
# for documentation purposes and will be used for sanity checking
# the existing FAT implementation.

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
