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

import sys
import os
import binascii
import base64

# Base64/32/16
def unpack_base64(fileresult, scanenvironment, offset, unpackdir):
    '''Convert a base64/base32/base16 file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # false positives: base64 files in Chrome PAK files
    if fileresult.parentlabels and 'pak' in fileresult.parentlabels:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'parent file PAK'}
        return {'status': False, 'error': unpackingerror}

    # add a cut off value to prevent many false positives
    base64cutoff = 8

    # sanity checks, before attempting to run base64 check: see
    # if there is a space in the file, which is not allowed in
    # any of the alphabets. Although whitespace "should be ignored"
    # in practice there are few files with extra whitespace characters.
    if filesize < base64cutoff:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'file too small'}
        return {'status': False, 'error': unpackingerror}

    # open the file in text mode
    checkfile = open(filename_full, 'r')
    linelengths = set()
    linectr = 0
    prevlinelength = sys.maxsize
    for i in checkfile:
        if " " in i.strip():
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid character not in base16/32/64 alphabets'}
            return {'status': False, 'error': unpackingerror}
        if i.strip() != '':
            if len(i) > prevlinelength:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'inconsistent line wrapping'}
                return {'status': False, 'error': unpackingerror}
            prevlinelength = len(i)
            linelengths.add(len(i))
            if len(linelengths) > 2:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'inconsistent line wrapping'}
                return {'status': False, 'error': unpackingerror}
        linectr += 1
    checkfile.close()

    # now read the whole file and run it through various decoders
    checkfile = open(filename_full, 'rb')
    base64contents = bytearray(filesize)
    checkfile.readinto(base64contents)
    checkfile.close()

    # first remove all the different line endings. These are not
    # valid characters in the base64 alphabet, plus it also conveniently
    # translates CRLF encoded files.
    base64contents = base64contents.replace(b'\n', b'')
    base64contents = base64contents.replace(b'\r', b'')

    decoded = False
    encoding = ''

    if linectr == 1:
        # a few sanity checks: there are frequently false positives
        # for MD5, SHA1, SHA256, etc.
        if len(base64contents) in [32, 40, 64]:
            try:
                binascii.unhexlify(base64contents)
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'inconsistent line wrapping'}
                return {'status': False, 'error': unpackingerror}
            except:
                pass

    # first base16
    try:
        decodedcontents = base64.b16decode(base64contents)
        decoded = True
        encoding = 'base16'
    except binascii.Error:
        pass

    # base32
    if not decoded:
        try:
            decodedcontents = base64.b32decode(base64contents)
            decoded = True
            encoding = 'base32'
        except binascii.Error:
            pass

    # base32, mapping
    if not decoded:
        try:
            decodedcontents = base64.b32decode(base64contents, map01='I')
            decoded = True
            encoding = 'base32'
        except binascii.Error:
            pass

    # base32, mapping
    if not decoded:
        try:
            decodedcontents = base64.b32decode(base64contents, map01='L')
            decoded = True
            encoding = 'base32'
        except binascii.Error:
            pass

    # regular base64
    if not decoded:
        invalidbase64 = False
        validbase64chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r')
        # check if the characters are in the base64 index table
        for i in base64contents:
            if chr(i) not in validbase64chars:
                invalidbase64 = True
                break
        if not invalidbase64:
            try:
                decodedcontents = base64.standard_b64decode(base64contents)
                if decodedcontents != b'':
                    # sanity check: in an ideal situation the base64 data is
                    # 1/3 larger than the decoded data.
                    # Anything 1.5 times larger (or more) is bogus.
                    # TODO: is this necessary? the decoder will not result in
                    # output larger than possible
                    if len(base64contents)/len(decodedcontents) < 1.5:
                        decoded = True
                        encoding = 'base64'
            except binascii.Error:
                pass

    # URL safe base64 (RFC 4648, section 5)
    if not decoded:
        invalidbase64 = False
        validbase64chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=\n\r')
        # check if the characters are in the base64 index table
        for i in base64contents:
            if chr(i) not in validbase64chars:
                invalidbase64 = True
                break
        if not invalidbase64:
            try:
                decodedcontents = base64.urlsafe_b64decode(base64contents)
                if decodedcontents != b'':
                    # sanity check: in an ideal situation the base64 data is
                    # 1/3 larger than the decoded data.
                    # Anything 1.5 times larger (or more) is bogus.
                    # TODO: is this necessary? the decoder will not result in
                    # output larger than possible
                    if len(base64contents)/len(decodedcontents) < 1.5:
                        decoded = True
                        encoding = 'base64'
                        labels.append('urlsafe')
            except binascii.Error:
                pass

    if not decoded:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid base64 file'}
        return {'status': False, 'error': unpackingerror}

    labels.append(encoding)

    # write the output to a file
    outfile_rel = os.path.join(unpackdir, "unpacked.%s" % encoding)
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    outfile.write(decodedcontents)
    outfile.close()

    unpackedfilesandlabels.append((outfile_rel, []))
    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_base64.pretty = 'base64'
unpack_base64.scope = 'text'
