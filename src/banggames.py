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

# Built in carvers/verifiers/unpackers for various game formats.
#
# For these unpackers it has been attempted to reduce disk I/O as much
# as possible using the os.sendfile() method, as well as techniques
# described in this blog post:
#
# https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import os


# Doom WAD files
#
# http://web.archive.org/web/20090530112359/http://www.gamers.org/dhs/helpdocs/dmsp1666.html
# Chapter 2
def unpack_doom_wad(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Doom WAD file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if offset + 12 > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # number of lumps in the file
    checkbytes = checkfile.read(4)
    nr_lumps = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    if nr_lumps == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no lumps defined'}
        return {'status': False, 'error': unpackingerror}

    # offset to beginning of the lumps directory
    checkbytes = checkfile.read(4)
    lumps_dir_offset = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    if offset + lumps_dir_offset + nr_lumps * 16 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for lumps directory'}
        return {'status': False, 'error': unpackingerror}

    maxoffset = lumps_dir_offset + nr_lumps * 16

    # now check the lumps directory
    checkfile.seek(offset + lumps_dir_offset)
    for lump in range(0, nr_lumps):
        # lump offset
        checkbytes = checkfile.read(4)
        lump_offset = int.from_bytes(checkbytes, byteorder='little')

        # lump size
        checkbytes = checkfile.read(4)
        lump_size = int.from_bytes(checkbytes, byteorder='little')

        # sanity check
        if offset + lump_offset + lump_size > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'data cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}

        maxoffset = max(maxoffset, lump_offset + lump_size)

        # lump name
        checkbytes = checkfile.read(8)
        try:
            lump_name = checkbytes.split(b'\x00', 1)[0].decode()
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid lump name'}
            return {'status': False, 'error': unpackingerror}

    if offset == 0 and maxoffset == filesize:
        labels.append('doom')
        labels.append('wad')
        labels.append('resource')
    else:
        # else carve the file
        outfile_rel = os.path.join(unpackdir, "unpacked.wad")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, maxoffset)
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, ['doom', 'wad', 'resource', 'unpacked']))

    checkfile.close()
    return {'status': True, 'length': maxoffset, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_doom_wad.signatures = {'doomwad': b'IWAD'}
unpack_doom_wad.minimum_size = 12
