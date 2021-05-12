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

import sys
import os
import binascii
import base64
import re
import pathlib

from FileResult import *


# https://en.wikipedia.org/wiki/Intel_HEX
# For now it is assumed that only files that are completely text
# files can be IHex files.
def unpack_ihex(fileresult, scanenvironment, offset, unpackdir):
    '''Convert an Intel Hex file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    allowbroken = False

    # open the file in text mode and process each line
    checkfile = open(filename_full, 'r')
    checkfile.seek(offset)

    outfile_rel = os.path.join(unpackdir, "unpacked-from-ihex")
    if filename_full.suffix.lower() == '.hex' or filename_full.suffix.lower() == '.ihex':
        outfile_rel = os.path.join(unpackdir, filename_full.stem)

    outfile_full = scanenvironment.unpack_path(outfile_rel)

    outfile_opened = False

    endofihex = False
    seenrecordtypes = set()

    # process each line until the end of the IHex data is read
    try:
        for line in checkfile:
            if not line.startswith(':'):
                # there could possibly be comments, starting with '#'
                if line.startswith('#'):
                    unpackedsize += len(line)
                    continue
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'line does not start with :'}
                return {'status': False, 'error': unpackingerror}
            # minimum length for a line is:
            # 1 + 2 + 4 + 2 + 2 = 11
            # Each byte uses two characters. The start code
            # uses 1 character.
            # That means that each line has an uneven length.
            if len(line.strip()) < 11 or len(line.strip()) % 2 != 1:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough bytes in line'}
                return {'status': False, 'error': unpackingerror}

            try:
                bytescount = int.from_bytes(bytes.fromhex(line[1:3]), byteorder='big')
            except:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not valid hex data'}
                return {'status': False, 'error': unpackingerror}

            if 3 + bytescount + 2 > len(line.strip()):
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert to hex'}
                return {'status': False, 'error': unpackingerror}

            # the base address is from 3:7 and can be skipped
            # the record type is next from 7:9
            try:
                recordtype = int.from_bytes(bytes.fromhex(line[7:9]), byteorder='big')
            except:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert to hex'}
                return {'status': False, 'error': unpackingerror}
            if recordtype > 5:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid record type'}
                return {'status': False, 'error': unpackingerror}

            computedchecksum = 0

            # record type 0 is data, record type 1 is end of data
            # Other record types do not include any data.
            if recordtype == 1:
                endofihex = True
            elif recordtype == 0:
                try:
                    ihexdata = bytes.fromhex(line[9:9+bytescount*2])
                except ValueError:
                    if outfile_opened:
                        checkfile.close()
                        outfile.close()
                        os.unlink(outfile_full)
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'cannot convert to hex'}
                    return {'status': False, 'error': unpackingerror}
                if not outfile_opened:
                    # create the unpacking directory
                    os.makedirs(unpackdir_full, exist_ok=True)
                    outfile = open(outfile_full, 'wb')
                    outfile_opened = True
                outfile.write(ihexdata)
            seenrecordtypes.add(recordtype)

            unpackedsize += len(line.strip()) + len(checkfile.newlines)

            if endofihex:
                break
    except UnicodeDecodeError:
        if outfile_opened:
            checkfile.close()
            outfile.close()
            os.unlink(outfile_full)
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}

    if outfile_opened:
        checkfile.close()
        outfile.close()

    if 4 in seenrecordtypes or 5 in seenrecordtypes:
        if 3 in seenrecordtypes:
            if outfile_opened:
                os.unlink(outfile_full)
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'incompatible record types combined'}
            return {'status': False, 'error': unpackingerror}

    # each valid IHex file has to have a terminator
    if not endofihex and not allowbroken:
        if outfile_opened:
            os.unlink(outfile_full)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no end of data found'}
        return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfile_rel, []))
    if offset == 0 and filesize == unpackedsize:
        labels.append('ihex')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_ihex.extensions = ['.hex', '.ihex']
unpack_ihex.pretty = 'ihex'
unpack_ihex.scope = 'text'


# https://en.wikipedia.org/wiki/SREC_(file_format)
# For now it is assumed that only files that are completely text
# files can be SREC files.
def unpack_srec(fileresult, scanenvironment, offset, unpackdir):
    '''Convert a SREC file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    allowbroken = False

    # open the file in text mode and process each line
    checkfile = open(filename_full, 'r')
    checkfile.seek(offset)

    outfile_rel = os.path.join(unpackdir, "unpacked-from-srec")
    if filename_full.suffix.lower() == '.srec':
        outfile_rel = os.path.join(unpackdir, filename_full.stem)
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    outfile_opened = False

    # process each line until the end of the SREC data is read
    seenheader = False
    seenterminator = False
    seenrecords = set()
    try:
        for line in checkfile:
            # keep track
            isdata = False
            if not line.startswith('S'):
                # there could possibly be comments, starting with ';',
                # although this is discouraged.
                if line.startswith(';'):
                    unpackedsize += len(line)
                    continue
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'line does not start with S'}
                return {'status': False, 'error': unpackingerror}

            # minimum length for a line is:
            # 2 + 2 + 4 + 2 = 10
            # Each byte uses two characters. The record type uses
            # two characters.
            # That means that each line has an even length.
            if len(line.strip()) < 10 or len(line.strip()) % 2 != 0:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough bytes in line'}
                return {'status': False, 'error': unpackingerror}

            # then the type. S0 is optional and has no data, S4 is
            # reserved and S5 and S6 are not that interesting.
            if line[:2] == 'S0':
                pass
            elif line[:2] == 'S1' or line[:2] == 'S2' or line[:2] == 'S3':
                isdata = True
            elif line[:2] == 'S7' or line[:2] == 'S8' or line[:2] == 'S9':
                seenterminator = True
            elif line[:2] == 'S4':
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'reserved S-Record value found'}
                return {'status': False, 'error': unpackingerror}
            else:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not an S-Record line'}
                return {'status': False, 'error': unpackingerror}
            recordtype = line[:2]
            seenrecords.add(recordtype)

            # then the byte count
            try:
                bytescount = int.from_bytes(bytes.fromhex(line[2:4]), byteorder='big')
            except ValueError:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert to hex'}
                return {'status': False, 'error': unpackingerror}
            if bytescount < 3:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'bytecount too small'}
                return {'status': False, 'error': unpackingerror}
            if 4 + bytescount * 2 != len(line.strip()):
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough bytes in line'}
                return {'status': False, 'error': unpackingerror}

            # skip the address field, or the count and read the data
            # Depending on the record type the amount of bytes that
            # the bytes count uses is different.
            try:
                if recordtype == 'S0':
                    # metadata that should not be part of the file
                    # TODO: store
                    srecdata = bytes.fromhex(line[8:8+(bytescount-3)*2])
                elif recordtype == 'S1':
                    srecdata = bytes.fromhex(line[8:8+(bytescount-3)*2])
                elif recordtype == 'S2':
                    srecdata = bytes.fromhex(line[10:10+(bytescount-4)*2])
                else:
                    srecdata = bytes.fromhex(line[12:12+(bytescount-5)*2])
            except ValueError:
                if outfile_opened:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfile_full)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert to hex'}
                return {'status': False, 'error': unpackingerror}

            if not outfile_opened:
                # create the unpacking directory
                os.makedirs(unpackdir_full, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile_opened = True
            # write the unpacked data to a file, but only for the
            # data records.
            if isdata:
                outfile.write(srecdata)
            unpackedsize += len(line.strip()) + len(checkfile.newlines)

            # no need to continue if a terminator was found
            if seenterminator:
                break

    except UnicodeDecodeError:
        if outfile_opened:
            checkfile.close()
            outfile.close()
            os.unlink(outfile_full)
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False, 'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}

    if outfile_opened:
        checkfile.close()
        outfile.close()

    # each valid SREC file has to have a terminator
    if not seenterminator and not allowbroken:
        if outfile_opened:
            os.unlink(outfile_full)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no terminator record found'}
        return {'status': False, 'error': unpackingerror}

    # sanity checks for the records:
    # only certain combinations are allowed
    if 'S1' in seenrecords:
        if 'S2' in seenrecords or 'S3' in seenrecords:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'incompatible data records mixed'}
            return {'status': False, 'error': unpackingerror}
        if 'S7' in seenrecords or 'S8' in seenrecords:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'incompatible terminator records mixed'}
            return {'status': False, 'error': unpackingerror}
    elif 'S2' in seenrecords:
        if 'S3' in seenrecords:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'incompatible data records mixed'}
            return {'status': False, 'error': unpackingerror}
        if 'S7' in seenrecords or 'S9' in seenrecords:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'incompatible terminator records mixed'}
            return {'status': False, 'error': unpackingerror}
    elif 'S3' in seenrecords:
        if 'S8' in seenrecords or 'S9' in seenrecords:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'incompatible terminator records mixed'}
            return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfile_rel, []))
    if offset == 0 and filesize == unpackedsize:
        labels.append('text')
        labels.append('srec')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_srec.extensions = ['.srec']
unpack_srec.pretty = 'srec'
unpack_srec.scope = 'text'


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
