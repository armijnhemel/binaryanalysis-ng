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
import shutil
import binascii
import string
import tempfile
import collections
import math
import tarfile
import lzma
import zlib
import zipfile
import bz2
import stat
import subprocess
import json
import xml.dom
import hashlib
import pathlib
import sqlite3

# some external packages that are needed
import defusedxml.minidom
import lz4
import lz4.frame
import mutf8
import pyaxmlparser

from parsers.archivers.cpio import UnpackParser as cpio_unpack

from FileResult import *
from UnpackParserException import UnpackParserException

encodingstotranslate = ['utf-8', 'ascii', 'latin-1', 'euc_jp', 'euc_jis_2004',
                        'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                        'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                        'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                        'shift_jis_2004', 'shift_jisx0213']

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


# Derived from public gzip specifications and Python module documentation
# The gzip format is described in RFC 1952
# https://tools.ietf.org/html/rfc1952
# sections 2.2 and 2.3
#
# gzip uses zlib's DEFLATE which is documented in RFC 1951
# https://tools.ietf.org/html/rfc1951
#
# Python's gzip module cannot be used, as it cannot correctly process
# gzip data if there is other non-gzip data following the gzip compressed
# data, so it has to be processed another way.
def unpack_gzip(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack gzip compressed data.'''
    filesize = fileresult.filesize
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    metadata = {}

    # treat CRC errors as fatal
    wrongcrcfatal = True

    filename_full = scanenvironment.unpack_path(fileresult.filename)

    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+3)
    unpackedsize += 3
    # RFC 1952 http://www.zlib.org/rfc-gzip.html describes the flags,
    # but omits the "encrytion" flag (bit 5)
    #
    # Python 3's zlib module does not support:
    # * continuation of multi-part gzip (bit 2)
    # * encrypt (bit 5)
    #
    # RFC 1952 says that bit 6 and 7 should not be set
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}
    flags = ord(checkbytes)
    if (flags >> 2 & 1) == 1:
        # continuation of multi-part gzip
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported multi-part gzip'}
        return {'status': False, 'error': unpackingerror}
    if (flags >> 5 & 1) == 1:
        # encrypted
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported encrypted'}
        return {'status': False, 'error': unpackingerror}
    if (flags >> 6 & 1) == 1 or (flags >> 7 & 1) == 1:
        # reserved
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not a valid gzip file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    havecrc16 = False
    # if bit one is set then there is a CRC16
    if (flags >> 1 & 1) == 1:
        havecrc16 = True

    havefextra = False
    # if bit two is set then there is extra info
    if (flags >> 2 & 1) == 1:
        havefextra = True

    havefname = False
    # if bit three is set then there is a name
    if (flags >> 3 & 1) == 1:
        havefname = True

    havecomment = False
    # if bit four is set then there is a comment
    if (flags >> 4 & 1) == 1:
        havecomment = True

    # skip over the MIME field
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # skip over the XFL and OS fields
    checkfile.seek(2, os.SEEK_CUR)
    unpackedsize += 2

    # optional XLEN
    if havefextra:
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data'}
            return {'status': False, 'error': unpackingerror}
        xlen = int.from_bytes(checkbytes, byteorder='little')
        if checkfile.tell() + xlen > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'extra data outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += xlen + 2

    # extract the original file name, if any
    # This can be used later to rename the file. Because of
    # false positives the name should not be checked now.
    if havefname:
        origname = b''
        while True:
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'file name data outside of file'}
                return {'status': False, 'error': unpackingerror}
            if checkbytes == b'\x00':
                unpackedsize += 1
                break
            origname += checkbytes
            unpackedsize += 1

    # then extract the comment
    origcomment = b''
    if havecomment:
        while True:
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'comment data outside of file'}
                return {'status': False, 'error': unpackingerror}
            if checkbytes == b'\x00':
                unpackedsize += 1
                break
            origcomment += checkbytes
            unpackedsize += 1
    try:
        metadata['comment'] = origcomment.decode()
    except UnicodeDecodeError:
        pass

    # skip over the CRC16, if present
    if havecrc16:
        checkfile.seek(2, os.SEEK_CUR)
        unpackedsize += 2

    # next are blocks of zlib compressed data
    # RFC 1951 section 3.2.3 describes the algorithm and also
    # an extra sanity check.
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}
    if (checkbytes[0] >> 1 & 1) == 1 and (checkbytes[0] >> 2 & 1) == 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong DEFLATE header'}
        return {'status': False, 'error': unpackingerror}

    # go back one byte
    checkfile.seek(-1, os.SEEK_CUR)

    # what follows next is raw deflate blocks. To unpack raw deflate
    # data the windowBits have to be set to negative values:
    # http://www.zlib.net/manual.html#Advanced
    # First create a zlib decompressor that can decompress raw deflate
    # https://docs.python.org/3/library/zlib.html#zlib.compressobj
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

    # now start decompressing the data
    # set the name of the file in case it is "anonymous data"
    # otherwise just imitate whatever gunzip does. If the file has a
    # name recorded in the file it will be renamed later.
    anonymous = False
    if filename_full.suffix.lower() == '.gz':
        outfile_rel = os.path.join(unpackdir, filename_full.stem)
    elif filename_full.suffix.lower() == '.tgz':
        outfile_rel = os.path.join(unpackdir, filename_full.stem + ".tar")
    else:
        outfile_rel = os.path.join(unpackdir, "unpacked-from-gz")
        anonymous = True

    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # open a file to write any unpacked data to
    os.makedirs(outfile_full.parent, exist_ok=True)
    outfile = open(outfile_full, 'wb')

    # store the CRC of the uncompressed data
    gzipcrc32 = zlib.crc32(b'')

    # then continue
    readsize = 10000000
    checkbuffer = bytearray(readsize)
    while True:
        bytesread = checkfile.readinto(checkbuffer)
        if bytesread == 0:
            break
        checkbytes = memoryview(checkbuffer[:bytesread])
        try:
            unpackeddata = decompressor.decompress(checkbytes)
            outfile.write(unpackeddata)
            gzipcrc32 = zlib.crc32(unpackeddata, gzipcrc32)
        except Exception as e:
            # clean up
            outfile.close()
            os.unlink(outfile_full)
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'File not a valid gzip file'}
            return {'status': False, 'error': unpackingerror}

        unpackedsize += bytesread - len(decompressor.unused_data)
        if decompressor.unused_data != b'':
            break
    outfile.close()

    # A valid gzip file has CRC32 and ISIZE at the end, so there should
    # always be at least 8 bytes left for a valid file.
    if filesize - unpackedsize + offset < 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no CRC and ISIZE'}
        return {'status': False, 'error': unpackingerror}

    # first reset the file pointer until the end of the unpacked zlib data
    checkfile.seek(offset + unpackedsize)

    # now compute the gzip CRC of the uncompressed data and compare to
    # the CRC stored in the file (RFC 1952, section 2.3.1)
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    if not gzipcrc32 == int.from_bytes(checkbytes, byteorder='little') and wrongcrcfatal:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong CRC'}
        return {'status': False, 'error': unpackingerror}

    # compute the ISIZE (RFC 1952, section 2.3.1)
    checkbytes = checkfile.read(4)
    checkfile.close()

    unpackedsize += 4

    # this check is modulo 2^32
    isize = os.stat(outfile_full).st_size % pow(2, 32)
    if int.from_bytes(checkbytes, byteorder='little') != isize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for ISIZE'}
        return {'status': False, 'error': unpackingerror}

    # now rename the file in case the file name was known
    if havefname:
        if origname != b'':
            origname = origname.decode()
            # in this case report the original name as well in a
            # different data structure
            try:
                movefile = True
                if '/' in origname:
                    origname = origname.split('/', 1)[0]
                    if origname != '':
                        movefile = False
                if movefile:
                    outfile_rel = os.path.join(unpackdir, origname)
                    new_outfile_full = scanenvironment.unpack_path(outfile_rel)
                    shutil.move(outfile_full, new_outfile_full)
                    outfile_full = new_outfile_full
                    anonymous = False
            except:
                pass

    # add the unpacked file to the result list
    if anonymous:
        unpackedfilesandlabels.append((outfile_rel, ['anonymous']))
    else:
        unpackedfilesandlabels.append((outfile_rel, []))

    # if the whole file is the gzip file add some more labels
    if offset == 0 and offset + unpackedsize == filesize:
        labels += ['gzip', 'compressed']

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels, 'metadata': metadata}

# gzip's specifications allow for multiple compression methods
# but RFC 1952 says x08 is the only compression method allowed
unpack_gzip.signatures = {'gzip': b'\x1f\x8b\x08'}


# wrapper for LZMA, with a few extra sanity checks based on
# LZMA format specifications.
def unpack_lzma(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack LZMA compressed data.'''
    filesize = fileresult.filesize
    unpackedfilesandlabels = []
    labels = []
    if filesize - offset < 13:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}

    filename_full = scanenvironment.unpack_path(fileresult.filename)

    # There are many false positives for LZMA.
    # The file lzma-file-format.txt in XZ file distributions describe
    # the LZMA format. The first 13 bytes describe the header. The last
    # 8 bytes of the header describe the file size.
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+5)
    checkbytes = checkfile.read(8)
    checkfile.close()

    # first check if an actual length of the *uncompressed* data is
    # stored, or if it is possibly stored as a stream. LZMA streams
    # have 0xffffffff stored in the length field.
    # http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
    if checkbytes != b'\xff\xff\xff\xff\xff\xff\xff\xff':
        lzmaunpackedsize = int.from_bytes(checkbytes, byteorder='little')
        if lzmaunpackedsize == 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'declared size 0'}
            return {'status': False, 'error': unpackingerror}

        # XZ Utils cannot unpack or create files > 256 GiB
        if lzmaunpackedsize > 274877906944:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'declared size too big'}
            return {'status': False, 'error': unpackingerror}
    else:
        lzmaunpackedsize = -1

    return unpack_lzma_wrapper(fileresult, scanenvironment, offset, unpackdir, '.lzma', 'lzma', 'LZMA', lzmaunpackedsize)

# most common signatures, although it won't catch everything, as the first
# bytes in LZMA will actually
# lzma_var1 is by far the most used
# lzma_var2 is seen a lot in OpenWrt
# lzma_var3 is used in some routers, like the ZyXEL NBG5615
unpack_lzma.signatures = {'lzma_var1': b'\x5d\x00\x00',
                          'lzma_var2': b'\x6d\x00\x00',
                          'lzma_var3': b'\x6c\x00\x00'}
unpack_lzma.pretty = 'lzma'
unpack_lzma.minimum_size = 13


# wrapper for both LZMA and XZ
# Uses standard Python code.
def unpack_lzma_wrapper(
        fileresult, scanenvironment, offset, unpackdir, extension,
        filetype, ppfiletype, lzmaunpackedsize):
    '''Wrapper method to unpack LZMA and XZ based files'''
    filesize = fileresult.filesize
    filename_full = pathlib.Path(scanenvironment.unpack_path(fileresult.filename))
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    unpackedsize = 0
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # Extract one 900k block of data as an extra sanity check.
    # First create a decompressor
    decompressor = lzma.LZMADecompressor()
    checkbuffer = bytearray(900000)
    bytesread = checkfile.readinto(checkbuffer)
    checkbytes = memoryview(checkbuffer[:bytesread])

    # then try to decompress the data.
    try:
        unpackeddata = decompressor.decompress(checkbytes)
    except Exception as e:
        # no data could be successfully unpacked
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not valid %s data' % ppfiletype}
        return {'status': False, 'error': unpackingerror}

    # set the name of the file in case it is "anonymous data"
    # otherwise just imitate whatever unxz and lzma do. If the file
    # has a name recorded in the file it will be renamed later.
    outfile_rel = os.path.join(unpackdir, "unpacked-from-%s" % filetype)
    if filetype == 'xz':
        if filename_full.suffix.lower() == '.xz':
            outfile_rel = os.path.join(unpackdir, filename_full.stem)
        elif filename_full.suffix.lower() == '.txz':
            outfile_rel = os.path.join(unpackdir, filename_full.stem) + ".tar"
    elif filetype == 'lzma':
        if filename_full.suffix.lower() == '.lzma':
            outfile_rel = os.path.join(unpackdir, filename_full.stem)
        elif filename_full.suffix.lower() == '.tlz':
            outfile_rel = os.path.join(unpackdir, filename_full.stem) + ".tar"
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # data has been unpacked, so open a file and write the data to it.
    # unpacked, or if all data has been unpacked
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    outfile.write(unpackeddata)
    unpackedsize += bytesread - len(decompressor.unused_data)

    # there is still some data left to be unpacked, so
    # continue unpacking, as described in the Python documentation:
    # https://docs.python.org/3/library/bz2.html#incremental-de-compression
    # https://docs.python.org/3/library/lzma.html
    bytesread = checkfile.readinto(checkbuffer)
    checkbytes = memoryview(checkbuffer[:bytesread])
    while bytesread != 0:
        try:
            unpackeddata = decompressor.decompress(checkbytes)
        except EOFError as e:
            break
        except Exception as e:
            # clean up
            outfile.close()
            os.unlink(outfile_full)
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'File not a valid %s file' % ppfiletype}
            return {'status': False, 'error': unpackingerror}
        outfile.write(unpackeddata)
        # there is no more compressed data
        unpackedsize += bytesread - len(decompressor.unused_data)
        if decompressor.unused_data != b'':
            break
        bytesread = checkfile.readinto(checkbuffer)
        checkbytes = memoryview(checkbuffer[:bytesread])
    outfile.close()
    checkfile.close()

    outfile_size = os.stat(outfile_full).st_size
    # ignore empty files, as it is bogus data
    if outfile_size == 0:
        os.unlink(outfile_full)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'File not a valid %s file' % ppfiletype}
        return {'status': False, 'error': unpackingerror}

    # check if the length of the unpacked LZMA data is correct, but
    # only if any unpacked length has been defined.
    if filetype == 'lzma' and lzmaunpackedsize != -1:
        if lzmaunpackedsize != outfile_size:
            os.unlink(outfile_full)
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'length of unpacked %s data does not correspond with header' % ppfiletype}
            return {'status': False, 'error': unpackingerror}

    min_lzma = 256

    # LZMA sometimes has bogus files filled with 0x00
    if outfile_size < min_lzma:
        pass

    if offset == 0 and unpackedsize == filesize:
        # in case the file name ends in extension rename the file
        # to mimic the behaviour of "unxz" and similar
        if filename_full.suffix.lower() == extension:
            outfile_rel = os.path.join(unpackdir, filename_full.stem)
            newoutfile_full = scanenvironment.unpack_path(outfile_rel)
            shutil.move(outfile_full, newoutfile_full)
            outfile_full = newoutfile_full
        labels += [filetype, 'compressed']
    unpackedfilesandlabels.append((outfile_rel, []))

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}


# XZ unpacking works just like LZMA unpacking
#
# XZ specifications:
#
# https://tukaani.org/xz/xz-file-format.txt
#
# XZ has some extra data (footer) that can be used for
# verifying the integrity of the file.
def unpack_xz(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack XZ compressed data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    allowbroken = True

    if not allowbroken:
        # header and footer combined are 24 bytes
        if filesize - offset < 24:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough bytes'}
            return {'status': False, 'error': unpackingerror}

    xzres = unpack_lzma_wrapper(fileresult, scanenvironment, offset, unpackdir, '.xz', 'xz', 'XZ', -1)
    if not allowbroken:
        # now check the header and footer, as the
        # stream flags have to be identical.
        if xzres['status']:
            # open the file again
            checkfile = open(filename_full, 'rb')

            # seek to where the streamflags start and read them
            checkfile.seek(offset+6)
            streamflagsheader = checkfile.read(2)

            # then seek to the end of the XZ file and
            # read the stream flags. This only works if
            # there are no padding bytes.
            checkfile.seek(offset+xzres['length'] - 4)
            streamflagsfooter = checkfile.read(2)
            footermagic = checkfile.read(2)
            checkfile.close()
            if streamflagsheader != streamflagsfooter:
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid stream flags in footer'}
                return {'status': False, 'error': unpackingerror}
            if footermagic != b'YZ':
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid footer magic'}
                return {'status': False, 'error': unpackingerror}
    return xzres

unpack_xz.signatures = {'xz': b'\xfd\x37\x7a\x58\x5a\x00'}
unpack_xz.minimum_size = 24


# unpacker for tar files. Uses the standard Python library.
# https://docs.python.org/3/library/tarfile.html
def unpack_tar(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack tar concatenated data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # tar is a concatenation of files. It could be that a tar file has
    # been cut halfway but it might still be possible to extract some
    # data. Use a file object so it is possible to start tar unpacking
    # at arbitrary positions in the file.
    checkfile = open(filename_full, 'rb')

    # seek to the offset where the tar is supposed to start. According
    # to the documentation it should be opened at offset 0, but this
    # works too.
    checkfile.seek(offset)
    try:
        unpacktar = tarfile.open(fileobj=checkfile, mode='r')
    except:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Not a valid tar file'}
        return {'status': False, 'error': unpackingerror}

    # record if something was unpacked and if something went wrong
    tarunpacked = False
    tarerror = False

    # keep track of which file names were already
    # unpacked. Files with the same name can be stored in a tar file
    # as it is just a concetanation of files.
    #
    # Test tar files with the same file twice are easily made:
    #
    # $ tar cf test.tar /path/to/file
    # $ tar --append -f test.tar /path/to/file
    unpackedtarfilenames = set()

    while True:
        # store the name of the file unpacked. This is needed to clean
        # up if something has gone wrong.
        tounpack = ''
        oldunpackedsize = checkfile.tell() - offset
        try:
            unpacktarinfo = unpacktar.next()
            if unpacktarinfo is None:
                break
            # don't unpack block devices, character devices or FIFO
            # https://docs.python.org/3/library/tarfile.html#tarfile.TarInfo.isdev
            if unpacktarinfo.isdev():
                continue
            tounpack = unpacktarinfo.name
            tarunpacked = True

            # unpack the file, after some sanity checks
            if os.path.normpath(unpacktarinfo.name) not in ['.', '..']:
                if os.path.isabs(unpacktarinfo.name):
                    tarname = os.path.relpath(unpacktarinfo.name, '/')
                    unpackedname = os.path.normpath(os.path.join(unpackdir, tarname))
                else:
                    unpackedname = os.path.normpath(os.path.join(unpackdir, unpacktarinfo.name))
                unpacked_full = scanenvironment.unpack_path(unpackedname)
                if os.path.isabs(unpacktarinfo.name):
                    os.makedirs(os.path.dirname(unpacked_full), exist_ok=True)
                    if unpacktarinfo.issym():
                        olddir = os.getcwd()
                        os.chdir(os.path.dirname(unpacked_full))
                        os.symlink(unpacktarinfo.linkname, os.path.basename(unpacked_full))
                        os.chdir(olddir)
                    elif unpacktarinfo.islnk():
                        olddir = os.getcwd()
                        os.chdir(os.path.dirname(unpacked_full))
                        if os.path.isabs(unpacktarinfo.linkname):
                            linkname = os.path.normpath(os.path.join(unpackdir, os.path.relpath(unpacktarinfo.linkname, '/')))
                            link_full = scanenvironment.unpack_path(linkname)
                            # TODO: better to link with relative path ../../..
                            if os.path.exists(link_full):
                                os.link(link_full, os.path.basename(unpacked_full))
                        os.chdir(olddir)
                    elif unpacktarinfo.isfile():
                        outfile = open(unpacked_full, 'wb')
                        tarreader = unpacktar.extractfile(unpacktarinfo)
                        outfile.write(tarreader.read())
                        outfile.close()
                    elif unpacktarinfo.isdir():
                        os.makedirs(unpacked_full, exist_ok=True)
                else:
                    unpackdir_full = scanenvironment.unpack_path(unpackdir)
                    unpacktar.extract(unpacktarinfo, path=unpackdir_full, set_attrs=False)
                unpackedsize = checkfile.tell() - offset

                # TODO: rename files properly with minimum chance of clashes
                if unpackedname in unpackedtarfilenames:
                    pass

                unpackedtarfilenames.add(unpackedname)
                if unpacktarinfo.isreg() or unpacktarinfo.isdir() or unpacktarinfo.issym() or unpacktarinfo.islnk():
                    # tar changes permissions after unpacking, so change
                    # them back to something a bit more sensible
                    if unpacktarinfo.isreg():
                        os.chmod(unpacked_full, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                        unpackedfilesandlabels.append((unpackedname, []))
                    elif unpacktarinfo.issym():
                        unpackedfilesandlabels.append((unpackedname, ['symbolic link']))
                    elif unpacktarinfo.islnk():
                        unpackedfilesandlabels.append((unpackedname, ['hardlink']))
                    elif unpacktarinfo.isdir():
                        os.chmod(unpacked_full, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                        unpackedfilesandlabels.append((unpackedname, ['directory']))
                    tounpack = ''
        except Exception as e:
            unpackedsize = oldunpackedsize
            tarerror = True
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': str(e)}
            if tounpack != '':
                unpackedname = os.path.join(unpackdir, unpackedname)
                unpacked_full = scanenvironment.unpack_path(unpackedname)
                if unpacked_full.exists():
                    if not os.path.islink(unpacked_full):
                        os.chmod(unpacked_full, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                    if os.path.isdir(unpacked_full) and not os.path.islink(unpacked_full):
                        shutil.rmtree(unpacked_full)
                    else:
                        os.unlink(unpacked_full)
            break

    # first close the TarInfo object, then the underlying fileobj
    unpacktar.close()
    if not tarunpacked:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Not a valid tar file'}
        return {'status': False, 'error': unpackingerror}

    # tar has finished, meaning it should also have read the termination
    # blocks for the tar file, so set the unpacked size to just after
    # where the tar module finished.
    unpackedsize = checkfile.tell() - offset

    # Data was unpacked from the file, so the data up until now is
    # definitely a tar, but is the rest of the file also part of the
    # tar or of something else?
    #
    # Example: GNU tar tends to pad files with up to 20 blocks (512
    # bytes each) filled with 0x00 although this heavily depends on
    # the command line settings.
    #
    # This can be checked with GNU tar by inspecting the file with the
    # options "itvRf" to the tar command:
    #
    # $ tar itvRf /path/to/tar/file
    #
    # These padding bytes are not read by Python's tarfile module and
    # need to be explicitly checked and flagged as part of the file
    if unpackedsize % 512 == 0:
        while offset + unpackedsize < filesize:
            checkbytes = checkfile.read(512)
            if len(checkbytes) != 512:
                break
            if checkbytes != b'\x00' * 512:
                break
            unpackedsize += 512
    if offset == 0 and unpackedsize == filesize:
        labels.append('tar')
        labels.append('archive')

    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# /usr/share/magic
unpack_tar.signatures = {'tar_posix': b'ustar\x00',
                         'tar_gnu': b'ustar\x20\x20\x00'}
unpack_tar.extensions = ['.tar']
unpack_tar.pretty = 'tar'
unpack_tar.offset = 0x101


# Unix portable archiver
# https://en.wikipedia.org/wiki/Ar_%28Unix%29
# https://sourceware.org/binutils/docs/binutils/ar.html
def unpack_ar(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack ar concatenated data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    unpackedsize = 0

    if offset != 0:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Currently only works on whole files'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('ar') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'ar program not found'}
        return {'status': False, 'error': unpackingerror}

    # first test the file to see if it is a valid file
    p = subprocess.Popen(['ar', 't', filename_full], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (standard_out, standard_error) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid ar file'}
        return {'status': False, 'error': unpackingerror}

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # then extract the file
    p = subprocess.Popen(['ar', 'x', filename_full], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=unpackdir_full)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        foundfiles = os.listdir(unpackdir_full)
        # try to remove any files that were left behind
        for f in foundfiles:
            if os.path.isdir(os.path.join(unpackdir_full, f)):
                shutil.rmtree(os.path.join(unpackdir_full, f))
            else:
                os.unlink(os.path.join(unpackdir_full, f))

        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid ar file'}
        return {'status': False, 'error': unpackingerror}

    foundfiles = os.listdir(unpackdir_full)
    labels += ['archive', 'ar']

    for f in foundfiles:
        outputfile_rel = os.path.join(unpackdir, f)
        outputfile_full = os.path.join(unpackdir_full, f)
        unpackedfilesandlabels.append((outputfile_rel, []))
        if f == 'debian-binary':
            if filename_full.suffix.lower() == '.deb' or filename_full.suffix.lower() == '.udeb':
                labels.append('debian')
                labels.append('deb')

    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_ar.signatures = {'ar': b'!<arch>'}


# ICC color profile
# Specifications: www.color.org/specification/ICC1v43_2010-12.pdf
# chapter 7.
#
# There are references throughout the code to ICC.1:2010, plus section
# numbers.
#
# Older specifications: http://www.color.org/icc_specs2.xalter
#
# Test files in package "colord" on for example Fedora
def unpack_icc(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve an ICC color profile file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # ICC.1:2010, section 7.1
    if filesize - offset < 128:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid ICC file'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # Then analyze the rest of the file
    # all numbers are big endian (ICC.1:2010, 7.1.2)

    # first the profile size, ICC.1:2010, 7.2.2
    # The ICC file can never be bigger than the profile size
    checkbytes = checkfile.read(4)
    profilesize = int.from_bytes(checkbytes, byteorder='big')
    if offset + profilesize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not enough data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # CMM field ICC.1:2010, 7.2.3, skip for now, as valid information
    # is in an online registry at www.color.org, so checks cannot
    # be hardcoded.
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # profile version field, ICC.1:2010, 7.2.4, skip for now
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # profile/device class field, ICC.1:2010 7.2.5
    profilefields = [b'scnr', b'mntr', b'prtr', b'link',
                     b'spac', b'abst', b'nmcl']

    checkbytes = checkfile.read(4)
    if checkbytes not in profilefields:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid profile/device class field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # data colour space field, ICC.1:2010, 7.2.6
    datacolourfields = [b'XYZ ', b'Lab ', b'Luv ', b'YCbr', b'Yxy ', b'RGB ',
                        b'GRAY', b'HSV ', b'HLS ', b'CMYK', b'CMY ', b'2CLR',
                        b'3CLR', b'4CLR', b'5CLR', b'6CLR', b'7CLR', b'8CLR',
                        b'9CLR', b'ACLR', b'BCLR', b'CCLR', b'DCLR', b'ECLR',
                        b'FCLR']
    checkbytes = checkfile.read(4)
    if checkbytes not in datacolourfields:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid profile/device class field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # PCS field, ICC.1:2010, 7.2.7, skip for now
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # date and time, ICC.1:2010, 7.2.8, skip for now
    checkfile.seek(12, os.SEEK_CUR)
    unpackedsize += 12

    # signature, ICC.1:2010, 7.2.9, already read, so skip
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # primary platform field, ICC.1:2010, 7.2.10
    checkbytes = checkfile.read(4)
    if checkbytes not in [b'APPL', b'MSFT', b'SGI ',
                          b'SUNW', b'\x00\x00\x00\x00']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid profile/device class field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # last 28 bytes of header should be 0x00, ICC.1:2010, 7.2.19
    checkfile.seek(offset+100)
    unpackedsize = 100
    checkbytes = checkfile.read(28)

    if not checkbytes == b'\x00' * 28:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved bytes not \\x00'}
        return {'status': False, 'error': unpackingerror}

    # skip to the tag table, ICC.1:2010, 7.3
    checkfile.seek(offset+128)
    unpackedsize = 128

    # the first 4 bytes are the tag count, ICC.1:2010 7.3.2
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no tag table'}
        return {'status': False, 'error': unpackingerror}
    tagcount = int.from_bytes(checkbytes, byteorder='big')
    # each tag is 12 bytes
    if offset + unpackedsize + 4 + tagcount * 12 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for tag table'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    maxtagoffset = 0
    for n in range(0, tagcount):
        checkbytes = checkfile.read(12)
        # first four bytes for a tag are the tag signature,
        # ICC.1:2010 7.3.3
        # skip for now.

        # next four bytes are the offset of the data, ICC.1:2010 7.3.4
        icctagoffset = int.from_bytes(checkbytes[4:8], byteorder='big')

        # tag offset has to be on a 4 byte boundary
        if icctagoffset % 4 != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid tag offset'}
            return {'status': False, 'error': unpackingerror}
        if offset + icctagoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'offset outside of file'}
            return {'status': False, 'error': unpackingerror}

        # then the size of the data, ICC.1:2010 7.3.5
        icctagsize = int.from_bytes(checkbytes[8:12], byteorder='big')
        if offset + icctagoffset + icctagsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data'}
            return {'status': False, 'error': unpackingerror}
        # add padding if necessary
        if icctagsize % 4 != 0:
            icctagsize += 4 - (icctagsize % 4)
        unpackedsize += 12

        maxtagoffset = max(maxtagoffset, offset + icctagoffset + icctagsize)

        # the tag offset cannot be outside of the declared profile size
        if maxtagoffset - offset > profilesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid tag offset'}
            return {'status': False, 'error': unpackingerror}

    if offset == 0 and maxtagoffset == filesize:
        checkfile.close()
        labels.append('icc')
        labels.append('resource')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.icc")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, maxtagoffset - offset)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['icc', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# http://www.color.org/specification/ICC1v43_2010-12.pdf, section 7.2
unpack_icc.signatures = {'icc': b'acsp'}
unpack_icc.offset = 36
unpack_icc.minimum_size = 128


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


# Derived from public bzip2 specifications
# and Python module documentation
def unpack_bzip2(fileresult, scanenvironment, offset, unpackdir, dryrun=False):
    '''Unpack bzip2 compressed data.'''
    filesize = fileresult.filesize
    filename_full = pathlib.Path(scanenvironment.unpack_path(fileresult.filename))
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 10:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 10 bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    unpackedsize = 0
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # Extract one 900k block of data as an extra sanity check.
    # First create a bzip2 decompressor
    bz2decompressor = bz2.BZ2Decompressor()
    bz2data = checkfile.read(900000)

    # then try to decompress the data.
    try:
        unpackeddata = bz2decompressor.decompress(bz2data)
    except Exception:
        # no data could be successfully unpacked,
        # so close the file and exit.
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'File not a valid bzip2 file'}
        return {'status': False, 'error': unpackingerror}

    # set the name of the file in case it is "anonymous data"
    # otherwise just imitate whatever bunzip2 does.
    # Special case: tbz2 (tar)
    if filename_full.suffix.lower() == '.bz2':
        outfile_rel = os.path.join(unpackdir, filename_full.stem)
    elif filename_full.suffix.lower() in ['.tbz', '.tbz2', '.tb2']:
        outfile_rel = os.path.join(unpackdir, filename_full.stem) + ".tar"
    else:
        outfile_rel = os.path.join(unpackdir, "unpacked-from-bz2")

    outfile_full = scanenvironment.unpack_path(outfile_rel)
    # data has been unpacked, so open a file and write the data to it.
    # unpacked, or if all data has been unpacked
    if not dryrun:
        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(unpackeddata)

    unpackedsize += len(bz2data) - len(bz2decompressor.unused_data)

    # there is still some data left to be unpacked, so
    # continue unpacking, as described in the Python documentation:
    # https://docs.python.org/3/library/bz2.html#incremental-de-compression
    # read some more data in chunks of 10 MB
    datareadsize = 10000000
    bz2data = checkfile.read(datareadsize)
    while bz2data != b'':
        try:
            unpackeddata = bz2decompressor.decompress(bz2data)
        except EOFError as e:
            break
        except Exception as e:
            # clean up
            if not dryrun:
                outfile.close()
                os.unlink(outfile_full)
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'File not a valid bzip2 file, use bzip2recover?'}
            return {'status': False, 'error': unpackingerror}

        if not dryrun:
            outfile.write(unpackeddata)

        # there is no more compressed data
        unpackedsize += len(bz2data) - len(bz2decompressor.unused_data)
        if bz2decompressor.unused_data != b'':
            break
        bz2data = checkfile.read(datareadsize)

    checkfile.close()

    if not dryrun:
        outfile.close()

        if offset == 0 and unpackedsize == filesize:
            labels += ['bzip2', 'compressed']
        unpackedfilesandlabels.append((outfile_rel, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# https://en.wikipedia.org/wiki/Bzip2#File_format
unpack_bzip2.signatures = {'bzip2': b'BZh'}
unpack_bzip2.minimum_size = 10


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


# http://www.nongnu.org/lzip/manual/lzip_manual.html#File-format
def unpack_lzip(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack lzip compressed data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize < 26:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then the version number, should be 1
    lzipversion = ord(checkfile.read(1))
    if lzipversion != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported lzip version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # then the LZMA dictionary size. The lowest 5 bits are
    # the dictionary base size.
    checkbytes = checkfile.read(1)
    dictionarybasesize = pow(2, ord(checkbytes) & 31)
    dictionarysize = dictionarybasesize - (int(dictionarybasesize/16)) * (ord(checkbytes) >> 5)
    unpackedsize += 1

    # create a LZMA decompressor with custom filter, as the data is
    # stored without LZMA headers. The LZMA properties are hardcoded
    # for lzip, except the dictionary.
    lzma_lc = 3
    lzma_lp = 0
    lzma_pb = 2

    lzip_filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': dictionarybasesize,
                     'lc': lzma_lc, 'lp': lzma_lp, 'pb': lzma_pb}]

    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=lzip_filters)
    if not filename_full.suffix.lower() == '.lz':
        outfile_rel = os.path.join(unpackdir, "unpacked-from-lzip")
    else:
        outfile_rel = os.path.join(unpackdir, filename_full.stem)
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')

    # while decompressing also compute the CRC of the uncompressed
    # data, as it is stored after the compressed LZMA data in the file
    crccomputed = binascii.crc32(b'')

    readsize = 1000000
    lzipbuffer = bytearray(readsize)
    bytesread = checkfile.readinto(lzipbuffer)
    checkbytes = lzipbuffer[:bytesread]

    while bytesread != 0:
        try:
            unpackeddata = decompressor.decompress(checkbytes)
        except EOFError as e:
            break
        except Exception as e:
            # clean up
            outfile.close()
            os.unlink(outfile_full)
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not valid LZMA data'}
            return {'status': False, 'error': unpackingerror}
        outfile.write(unpackeddata)
        crccomputed = binascii.crc32(unpackeddata, crccomputed)
        # there is no more compressed data
        unpackedsize += bytesread - len(decompressor.unused_data)
        if decompressor.unused_data != b'':
            break
        bytesread = checkfile.readinto(lzipbuffer)
        checkbytes = lzipbuffer[:bytesread]

    outfile.close()

    # first reset to the end of the LZMA compressed data
    checkfile.seek(offset+unpackedsize)

    # then four bytes of CRC32
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for CRC'}
        return {'status': False, 'error': unpackingerror}

    crcstored = int.from_bytes(checkbytes, byteorder='little')
    # the CRC stored is the CRC of the uncompressed data
    if crcstored != crccomputed:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong CRC'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # then the size of the original uncompressed data
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for original data size'}
        return {'status': False, 'error': unpackingerror}
    originalsize = int.from_bytes(checkbytes, byteorder='little')
    if originalsize != os.stat(outfile_full).st_size:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong original data size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # then the member size
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for member size'}
        return {'status': False, 'error': unpackingerror}
    membersize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    # the member size has to be the same as the unpacked size
    if membersize != unpackedsize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong member size'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, []))
    if offset == 0 and unpackedsize == filesize:
        labels.append('compressed')
        labels.append('lzip')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# http://www.nongnu.org/lzip/manual/lzip_manual.html#File-format
unpack_lzip.signatures = {'lzip': b'LZIP'}
unpack_lzip.minimum_size = 26


# Derived from specifications at:
# https://www.w3.org/TR/WOFF/
# section 3 and 4 describe the format
def unpack_woff(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a WOFF font file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    checkfile = open(filename_full, 'rb')
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # skip over the header
    checkfile.seek(offset+4)
    unpackedsize += 4

    # next 4 bytes are the "flavour" of the font. Don't use for now.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for font flavour'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # next 4 bytes are the size of the font.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for font size'}
        return {'status': False, 'error': unpackingerror}

    # the font cannot be outside of the file
    fontsize = int.from_bytes(checkbytes, byteorder='big')
    if offset + fontsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'declared font size outside file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # next the number of tables
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for number of tables'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    numtables = int.from_bytes(checkbytes, byteorder='big')

    # next a reserved field. Should be set to 0
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for reserved field'}
        return {'status': False, 'error': unpackingerror}
    if int.from_bytes(checkbytes, byteorder='big') != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved field not 0'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # next the totalSfntSize. This field must be divisible by 4.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for totalSfntSize'}
        return {'status': False, 'error': unpackingerror}
    if int.from_bytes(checkbytes, byteorder='big') % 4 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not aligned on 4 byte boundary'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # then the major version
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for major version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # and the minor version
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for minor version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # the location of the meta data block. This offset cannot be
    # outside the file.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for meta data block location'}
        return {'status': False, 'error': unpackingerror}
    metaoffset = int.from_bytes(checkbytes, byteorder='big')
    if offset + metaoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'meta data block cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    # the private data block MUST start on a 4 byte boundary (section 7)
    if metaoffset % 4 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'meta data doesn\'t start on 4 byte boundary'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the length of the compressed meta data block. This cannot be
    # outside the file.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for compressed meta data block'}
        return {'status': False, 'error': unpackingerror}
    metalength = int.from_bytes(checkbytes, byteorder='big')
    if offset + metaoffset + metalength > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'meta data block end outside file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # then the original length of the meta data. Ignore for now.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for original meta data length'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the location of the private data block. This offset cannot be
    # outside the file.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for private data block location'}
        return {'status': False, 'error': unpackingerror}
    privateoffset = int.from_bytes(checkbytes, byteorder='big')
    if offset + privateoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'private data block cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    # the private data block MUST start on a 4 byte boundary (section 8)
    if privateoffset % 4 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'private data block doesn\'t start on 4 byte boundary'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the length of the private data block.
    # This cannot be outside the file.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for private data block'}
        return {'status': False, 'error': unpackingerror}
    privatelength = int.from_bytes(checkbytes, byteorder='big')
    if offset + privateoffset + privatelength > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'private data block cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # then the "table directory"
    lastseenoffset = 0
    for t in range(0, numtables):
        # the tag of the table
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for tag table'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # the offset of the table. This cannot be outside of the file.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for table offset'}
            return {'status': False, 'error': unpackingerror}
        tableoffset = int.from_bytes(checkbytes, byteorder='big')
        if offset + tableoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'table offset cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # then the length of the compressed data, excluding padding
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for compressed table length'}
            return {'status': False, 'error': unpackingerror}
        tablecompressedlength = int.from_bytes(checkbytes, byteorder='big')
        if offset + tableoffset + tablecompressedlength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'compressed data cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # then the length of the uncompressed data, excluding padding.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for uncompressed table length'}
            return {'status': False, 'error': unpackingerror}
        tableuncompressedlength = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        # then the checksum of the uncompressed data.
        # Can be ignored for now
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for uncompressed data checksum'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # If the compressed length is the same as uncompressed,
        # then the data is stored uncompressed. Since this has
        # already been verified in an earlier check there is no
        # need to further check (section 5 of specifications).

        if tablecompressedlength < tableuncompressedlength:
            # Then jump to the right place in the file (tableoffset)
            # and read the bytes.
            # first store the old offset
            prevoffset = checkfile.tell()
            checkfile.seek(offset+tableoffset)
            checkbytes = checkfile.read(tablecompressedlength)

            # then try to decompress the bytes read with zlib
            zlibdecompressor = zlib.decompressobj()
            try:
                uncompresseddata = zlibdecompressor.decompress(checkbytes)
                if len(uncompresseddata) != tableuncompressedlength:
                    pass
            except:
                checkfile.close()
                unpackingerror = {'offset': offset+tableoffset,
                                  'fatal': False,
                                  'reason': 'invalid compressed data in font'}
                return {'status': False, 'error': unpackingerror}
            checkfile.seek(offset+tableoffset)

            # then return to the previous offset
            checkfile.seek(prevoffset)

        # store the last valid offset seen. Fonts don't need to
        # appear in order in the font table.
        lastseenoffset = max(lastseenoffset, offset + tableoffset + tablecompressedlength)

    # set the unpackedsize to the maximum of the last seen offset and
    # the unpacked size. This is done in case the font table is empty.
    unpackedsize = max(lastseenoffset, unpackedsize) - offset

    # the declared fontsize cannot be smaller than what was unpacked
    if unpackedsize > fontsize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'size of unpacked data larger than declared font size'}
        return {'status': False, 'error': unpackingerror}

    # it could be that there is padding. There should be a maximum
    # of three bytes for padding.
    if fontsize - unpackedsize > 3:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'declared font size too large for unpacked data'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = fontsize

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels += ['woff', 'font', 'resource']
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked-woff")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['woff', 'font', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_woff.signatures = {'woff': b'wOFF'}


# a generic method for unpacking fonts:
#
# * TTF
# * OTF
#
# These fonts have a similar structure, but differ in the magic
# header and the required tables.
def unpack_font(fileresult, scanenvironment, offset, unpackdir,
                fontextension, collectionoffset=None):
    '''Helper method to unpack various fonts'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    checkfile = open(filename_full, 'rb')

    # skip the magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then the number of tables
    checkbytes = checkfile.read(2)
    numtables = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    if numtables == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False, 'reason': 'no tables defined'}
        return {'status': False, 'error': unpackingerror}

    # followed by the searchRange
    checkbytes = checkfile.read(2)
    searchrange = int.from_bytes(checkbytes, byteorder='big')

    # the search range is defined
    # as (maximum power of 2 <= numTables)*16
    if pow(2, int(math.log2(numtables)))*16 != searchrange:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'number of tables does not correspond to search range'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # then the entryselector, which is defined
    # as log2(maximum power of 2 <= numTables)
    checkbytes = checkfile.read(2)
    entryselector = int.from_bytes(checkbytes, byteorder='big')
    if int(math.log2(numtables)) != entryselector:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'number of tables does not correspond to entrySelector'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # then the rangeshift
    checkbytes = checkfile.read(2)
    rangeshift = int.from_bytes(checkbytes, byteorder='big')
    if rangeshift != numtables * 16 - searchrange:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'rangeshift does not correspond to rest of header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    tablesseen = set()

    maxoffset = -1

    tablenametooffset = {}

    # There are fonts that are not 4 byte aligned. Computing checksums
    # for these is more difficult, as it is unclear whether or not
    # padding should be added or not.
    # https://lists.w3.org/Archives/Public/public-webfonts-wg/2010Jun/0063.html
    #
    # For the checksums in individual tables it is imperative to add
    # a few "virtual NUL bytes" to make sure that the checksum can be
    # computed correctly. However, this doesn't seem to be working for
    # the checkSumAdjustment value.

    addbytes = 0
    fontname = ''
    seenhead = False

    # then read the table directory, with one entry per table
    for i in range(0, numtables):
        # first the table name
        tablename = checkfile.read(4)
        if len(tablename) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table name'}
            return {'status': False, 'error': unpackingerror}

        # each table can only appear once
        if tablename in tablesseen:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'duplicate table name'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        tablesseen.add(tablename)

        # store the checksum for this table to check later
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table checksum'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        tablechecksum = int.from_bytes(checkbytes, byteorder='big')

        # then the offset to the actual data
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table offset'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        tableoffset = int.from_bytes(checkbytes, byteorder='big')

        # store where the data for each table starts
        tablenametooffset[tablename] = tableoffset

        # then the length of the data
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table length'}
            return {'status': False, 'error': unpackingerror}
        tablelength = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        if collectionoffset is not None:
            if collectionoffset + tableoffset + tablelength > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table'}
                return {'status': False, 'error': unpackingerror}
        else:
            if offset + tableoffset + tablelength > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table'}
                return {'status': False, 'error': unpackingerror}

        # then compute the checksum for the table
        # First store the old offset, so it is possible
        # to return.
        oldoffset = checkfile.tell()
        if collectionoffset is not None:
            checkfile.seek(collectionoffset + tableoffset)
        else:
            checkfile.seek(offset + tableoffset)
        padding = 0

        # tables are 4 byte aligned (long)
        if tablelength % 4 != 0:
            padding = 4 - tablelength % 4

        bytesadded = False

        # extra sanity check, as there might now be padding bytes
        checkbuf = checkfile.read(tablelength + padding)
        if len(checkbuf) != tablelength + padding:
            if len(checkbuf) == tablelength:
                checkbuf += b'\x00' * padding
                addbytes = padding
                bytesadded = True
            else:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table'}
                return {'status': False, 'error': unpackingerror}

        checkbytes = memoryview(checkbuf)

        # parse the name table to see if there is a font name
        # https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6name.html
        if tablename == b'name':
            localoffset = 0
            if len(checkbytes) < 6:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data in name table'}
                return {'status': False, 'error': unpackingerror}

            # first the format selector ("set to 0"). Skip.
            # then the name count to indicate how many name records
            # (12 bytes each) are present in the name table
            namecount = int.from_bytes(checkbytes[2:4], byteorder='big')
            if len(checkbytes) < 6 + namecount * 12:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data in name table'}
                return {'status': False, 'error': unpackingerror}

            # then the offset of the name table strings
            nametablestringoffset = int.from_bytes(checkbytes[4:6], byteorder='big')
            if len(checkbytes) < 6 + namecount * 12 + nametablestringoffset:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data in name table'}
                return {'status': False, 'error': unpackingerror}

            localoffset = 6
            for n in range(0, namecount):
                # first platform id
                platformid = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                # skip platform specific id and language id
                localoffset += 4

                # then the nameid
                nameid = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                # then the name length
                namelength = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                # then the name offset
                nameoffset = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                # extract the font name if it exists
                if namelength != 0:
                    if nameid == 6:
                        if platformid in [0, 1]:
                            fontname = checkbytes[nametablestringoffset+nameoffset:nametablestringoffset+nameoffset+namelength]
        computedsum = 0
        for j in range(0, tablelength + padding, 4):
            computedsum += int.from_bytes(checkbytes[j:j+4], byteorder='big')

        # only grab the lowest 32 bits (4294967295 = (2^32)-1)
        computedsum = computedsum & 4294967295
        if tablename != b'head':
            if tablechecksum != computedsum:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'checksum for table incorrect'}
                return {'status': False, 'error': unpackingerror}
        else:
            # the head table checksum is different and uses a
            # checksum adjustment, which is documented here:
            # https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6head.html
            # First seek to the start of the table and then skip 8 bytes
            if collectionoffset is not None:
                checkfile.seek(collectionoffset + tableoffset + 8)
            else:
                checkfile.seek(offset + tableoffset + 8)
            checkbytes = checkfile.read(4)
            checksumadjustment = int.from_bytes(checkbytes, byteorder='big')
            seenhead = True

        # then store the maxoffset, including padding, but minus
        # any "virtual" bytes
        if bytesadded:
            if collectionoffset is not None:
                maxoffset = max(maxoffset, collectionoffset + tableoffset + tablelength + padding - addbytes)
            else:
                maxoffset = max(maxoffset, offset + tableoffset + tablelength + padding - addbytes)
        else:
            if collectionoffset is not None:
                maxoffset = max(maxoffset, collectionoffset + tableoffset + tablelength + padding)
            else:
                maxoffset = max(maxoffset, offset + tableoffset + tablelength + padding)

        # and return to the old offset for the next entry
        checkfile.seek(oldoffset)

    unpackedsize = maxoffset - offset

    if not seenhead:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a font file'}
        return {'status': False, 'error': unpackingerror}

    # in case the file is a font collection it ends here.
    if collectionoffset is not None:
        checkfile.close()
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # now compute the checksum for the whole font. It is important
    # that checkSumAdjustment is set to 0 during this computation.
    # It should be noted that for some fonts (where padding was added
    # to the last table) this computation might be wrong.
    fontchecksum = 0
    checkfile.seek(offset)
    for i in range(0, unpackedsize, 4):
        if i == tablenametooffset[b'head'] + 8:
            checkfile.seek(4, os.SEEK_CUR)
            continue
        checkbytes = checkfile.read(4)
        if unpackedsize - i < 4 and addbytes != 0:
            checkbytes += b'\x00' * addbytes
        fontchecksum += int.from_bytes(checkbytes, byteorder='big')

    # only grab the lowest 32 bits (4294967295 = (2^32)-1)
    fontchecksum = fontchecksum & 4294967295

    if checksumadjustment != 0xB1B0AFBA - fontchecksum:
        # some fonts, such as the the Ubuntu ones use a different
        # value for checksumadjustment
        if checksumadjustment != 0x1B1B0AFBA - fontchecksum:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'checksum adjustment does not match computed value'}
            return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('font')
        labels.append('resource')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels,
                'tablesseen': tablesseen}

    # else carve the file
    # if the name was extracted from the 'name' table it could possibly
    # be used for the extracted file.
    if fontname != '':
        try:
            fontname = bytes(fontname).decode()
            outfile_rel = os.path.join(unpackdir, fontname + "." + fontextension)
        except UnicodeDecodeError:
            outfile_rel = os.path.join(unpackdir, "unpacked." + fontextension)
    else:
        outfile_rel = os.path.join(unpackdir, "unpacked." + fontextension)

    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['font', 'resource', 'unpacked']))
    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels, 'tablesseen': tablesseen}


# https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html
def unpack_truetype_font(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a TrueType font file.'''
    filesize = fileresult.filesize
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # font header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid font file'}
        return {'status': False, 'error': unpackingerror}

    # https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html
    # (table 2)
    # the following tables are required for a TrueType font:
    requiredtables = set([b'cmap', b'glyf', b'head', b'hhea', b'hmtx',
                          b'loca', b'maxp', b'name', b'post'])

    fontres = unpack_font(fileresult, scanenvironment, offset, unpackdir, 'ttf')
    if not fontres['status']:
        return fontres

    labels = fontres['labels']
    unpackedfilesandlabels = fontres['filesandlabels']

    # first check if all the required tables are there.
    # It could be that the font is actually a "sfnt-housed font" and
    # then not all the tables need to be there.
    if not fontres['tablesseen'].intersection(requiredtables) == requiredtables:
        if offset == 0 and fontres['length'] == filesize:
            labels.append('sfnt')
        else:
            # fix labels for the carved file
            unpackedfilesandlabels[0][1].append('sfnt')
    else:
        if offset == 0 and fontres['length'] == filesize:
            labels.append('TrueType')
        else:
            # fix labels for the carved file
            unpackedfilesandlabels[0][1].append('TrueType')
    return {'status': True, 'length': fontres['length'], 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_truetype_font.signatures = {'truetype': b'\x00\x01\x00\x00'}
unpack_truetype_font.minimum_size = 12


# https://docs.microsoft.com/en-us/typography/opentype/spec/otff
def unpack_opentype_font(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve an OpenType font file.'''
    filesize = fileresult.filesize
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # font header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid font file'}
        return {'status': False, 'error': unpackingerror}

    # https://docs.microsoft.com/en-us/typography/opentype/spec/otff
    # (section 'Font Tables')
    # the following tables are required in a font:
    requiredtables = set([b'cmap', b'head', b'hhea', b'hmtx',
                          b'maxp', b'name', b'OS/2', b'post'])

    fontres = unpack_font(fileresult, scanenvironment, offset, unpackdir, 'otf')
    if not fontres['status']:
        return fontres

    # first check if all the required tables are there.
    if not fontres['tablesseen'].intersection(requiredtables) == requiredtables:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not all required tables present'}
        return {'status': False, 'error': unpackingerror}

    labels = fontres['labels']
    unpackedfilesandlabels = fontres['filesandlabels']
    if offset == 0 and fontres['length'] == filesize:
        labels.append('OpenType')
    else:
        # fix labels for the carved file
        unpackedfilesandlabels[0][1].append('OpenType')
    return {'status': True, 'length': fontres['length'], 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_opentype_font.signatures = {'opentype': b'OTTO'}
unpack_opentype_font.minimum_size = 12


# Multiple fonts can be stored in font collections. The offsets
# recorded in the fonts are relative to the start of the collection
# not to the font itself.
# https://docs.microsoft.com/en-us/typography/opentype/spec/otff
#
# Good test files in google-noto-sans-cjk-ttc-fonts (name of Fedora package)
def unpack_opentype_font_collection(
        fileresult, scanenvironment, offset,
        unpackdir):
    '''Verify an OpenType font collection file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # https://docs.microsoft.com/en-us/typography/opentype/spec/otff
    # (section 'Font Tables')
    # the following tables are required in a font:
    requiredtables = set([b'cmap', b'head', b'hhea', b'hmtx',
                          b'maxp', b'name', b'OS/2', b'post'])

    # font collection header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid font file'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize = 4

    # major version, only support version 1 right now
    checkbytes = checkfile.read(2)
    majorversion = int.from_bytes(checkbytes, byteorder='big')
    if majorversion != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported major version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # minor version, has to be 0
    checkbytes = checkfile.read(2)
    minorversion = int.from_bytes(checkbytes, byteorder='big')
    if minorversion != 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported minor version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # number of fonts
    checkbytes = checkfile.read(4)
    numfonts = int.from_bytes(checkbytes, byteorder='big')
    if numfonts == 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no fonts declared'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    maxoffset = 0

    # offsets for each font
    for i in range(0, numfonts):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for font offsets'}
            return {'status': False, 'error': unpackingerror}
        fontoffset = int.from_bytes(checkbytes, byteorder='big')
        if offset + fontoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'font offset table outside of file'}
            return {'status': False, 'error': unpackingerror}
        fontres = unpack_font(fileresult, scanenvironment, offset + fontoffset, unpackdir, 'otf', collectionoffset=offset)
        if not fontres['status']:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'font verification failed'}
            return {'status': False, 'error': unpackingerror}
        maxoffset = fontres['length'] + fontoffset

    checkfile.close()

    if offset == 0 and maxoffset == filesize:
        labels.append('fontcollection')
        labels.append('resource')
        return {'status': True, 'length': filesize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'not a valid font collection file or unsupported file'}
    return {'status': False, 'error': unpackingerror}

unpack_opentype_font_collection.signatures = {'ttc': b'ttcf'}
unpack_opentype_font_collection.minimum_size = 12


# https://rzip.samba.org/
# https://en.wikipedia.org/wiki/Rzip
def unpack_rzip(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack rzip compressed data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize - offset < 10:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 10 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('rzip') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'rzip program not found'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename_full, 'rb')

    # skip over the header
    checkfile.seek(offset+4)
    unpackedsize = 4

    # then read the major version
    checkbytes = checkfile.read(1)
    unpackedsize += 1

    if ord(checkbytes) > 2:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid major version number %d' % ord(checkbytes)}
        return {'status': False, 'error': unpackingerror}

    # then read the minor version
    checkbytes = checkfile.read(1)
    unpackedsize += 1

    # then read the size of the uncompressed data
    checkbytes = checkfile.read(4)
    uncompressedsize = int.from_bytes(checkbytes, byteorder='big')

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # check if there actually is bzip2 compressed data.
    bzip2headerfound = False
    while True:
        while True:
            oldpos = checkfile.tell()
            checkbytes = checkfile.read(200)
            if len(checkbytes) == 0:
                break
            bzip2pos = checkbytes.find(b'BZh')
            if bzip2pos != -1:
                bzip2pos += oldpos
                bzip2headerfound = True
                break
            if len(checkbytes) > 4:
                checkfile.seek(-4, os.SEEK_CUR)

        # no bzip2 data was found, so it is not a valid rzip file
        if not bzip2headerfound:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no valid bzip2 header found'}
            return {'status': False, 'error': unpackingerror}

        # uncompress the bzip2 data
        bzip2res = unpack_bzip2(fileresult, scanenvironment, bzip2pos, unpackdir, dryrun=True)
        if not bzip2res['status']:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no valid bzip2 data'}
            return {'status': False, 'error': unpackingerror}

        checkfile.seek(bzip2pos + bzip2res['length'])
        unpackedsize = checkfile.tell() - offset

        # check if there could be another block with bzip2 data
        # the data between the bzip2 blocks is 13 bytes, see
        # rzip source code, file: stream.c, function: fill_buffer()
        if filesize - (bzip2res['length'] + bzip2pos) < 13:
            break

        checkfile.seek(13, os.SEEK_CUR)
        checkbytes = checkfile.read(3)
        if checkbytes != b'BZh':
            break

        checkfile.seek(-3, os.SEEK_CUR)

    if not filename_full.suffix.lower() == '.rz':
        outfile_rel = os.path.join(unpackdir, "unpacked-from-rzip")
    else:
        outfile_rel = os.path.join(unpackdir, filename_full.stem)
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        p = subprocess.Popen(['rzip', '-k', '-d', filename_full, '-o', outfile_full], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid RZIP file'}
            return {'status': False, 'error': unpackingerror}
        if os.stat(outfile_full).st_size != uncompressedsize:
            os.unlink(outfile_full)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unpacked RZIP data does not match declared uncompressed size'}
            return {'status': False, 'error': unpackingerror}
        unpackedfilesandlabels.append((outfile_rel, []))
        labels.append('compressed')
        labels.append('rzip')

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
    os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
    os.fdopen(temporaryfile[0]).close()
    checkfile.close()
    p = subprocess.Popen(['rzip', '-d', temporaryfile[1], '-o', outfile_full], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        os.unlink(temporaryfile[1])
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid RZIP file'}
        return {'status': False, 'error': unpackingerror}
    if os.stat(outfile_full).st_size != uncompressedsize:
        os.unlink(outfile_full)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unpacked RZIP data does not match declared uncompressed size'}
        return {'status': False, 'error': unpackingerror}
    unpackedfilesandlabels.append((outfile_rel, []))

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# /usr/share/magic
unpack_rzip.signatures = {'rzip': b'RZIP'}
unpack_rzip.minimum_size = 10


# Windows Compiled HTML help
# https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help
# http://web.archive.org/web/20021209123621/www.speakeasy.org/~russotto/chm/chmformat.html
def unpack_chm(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a Windows Compiled HTML file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # header has at least 56 bytes
    if filesize < 56:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic and the version number
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    # total header length
    checkbytes = checkfile.read(4)
    chmheaderlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + chmheaderlength > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'declared header outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # skip over the rest of the header
    checkfile.seek(offset + 56)
    unpackedsize = 56

    # the header section table
    for i in range(0, 2):
        # a section offset
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for section offset'}
            return {'status': False, 'error': unpackingerror}
        sectionoffset = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 8

        # and a section size
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for section size'}
            return {'status': False, 'error': unpackingerror}
        sectionsize = int.from_bytes(checkbytes, byteorder='little')

        # sanity check: sections cannot be outside of the file
        if offset + sectionoffset + sectionsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'sections outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 8

    # then the offset of content section 0, that isn't there in version 2,
    # but version 2 is not supported anyway.
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for content section offset'}
        return {'status': False, 'error': unpackingerror}
    contentsection0offset = int.from_bytes(checkbytes, byteorder='little')
    if offset + contentsection0offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'content section 0 outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # then skip 8 bytes
    checkfile.seek(8, os.SEEK_CUR)
    unpackedsize += 8

    # read the file size
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for file size'}
        return {'status': False, 'error': unpackingerror}
    chmsize = int.from_bytes(checkbytes, byteorder='little')
    if offset + chmsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'declared CHM size larger than file size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    if shutil.which('7z') is None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': '7z program not found'}
        return {'status': False, 'error': unpackingerror}
    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'not a valid CHM file'}

    unpackedsize = chmsize

    havetmpfile = False
    if not (offset == 0 and filesize == unpackedsize):
        temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir_full, '-y', 'x', temporaryfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if offset == 0 and filesize == unpackedsize:
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir_full, '-y', 'x', filename_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        # cleanup
        if havetmpfile:
            os.unlink(temporaryfile[1])
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid CHM file'}
        return {'status': False, 'error': unpackingerror}

    dirwalk = os.walk(unpackdir_full)
    for direntries in dirwalk:
        # make sure all subdirectories and files can be accessed
        for subdir in direntries[1]:
            subdirname = os.path.join(direntries[0], subdir)
            if not os.path.islink(subdirname):
                os.chmod(subdirname, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        for fn in direntries[2]:
            fullfilename = os.path.join(direntries[0], fn)
            relfilename = scanenvironment.rel_unpack_path(fullfilename)
            unpackedfilesandlabels.append((relfilename, []))

    # cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])
    else:
        labels.append('chm')
        labels.append('compressed')
        labels.append('resource')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# full signature in /usr/share/magic
# this is only a part and only for version 3
unpack_chm.signatures = {'chm': b'ITSF\x03\x00\x00\x00'}
unpack_chm.minimum_size = 56


# Windows Imaging Format
#
# This format has been described by Microsoft here:
#
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749478(v=ws.10)
#
# but is currently not under the open specification promise
#
# Windows data types can be found here:
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
def unpack_wim(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a Windows Imaging Format file file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # a WIM signature header is at least 208 bytes
    if filesize - offset < 208:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset + 8)
    unpackedsize += 8

    # now read the size of the header
    checkbytes = checkfile.read(4)
    headersize = int.from_bytes(checkbytes, byteorder='little')
    if headersize < 208:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid header size'}
        return {'status': False, 'error': unpackingerror}
    if offset + headersize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'declared header size bigger than file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the WIM file format version, unused for now
    checkbytes = checkfile.read(4)
    wimversion = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # WIM flags, unused for now
    checkbytes = checkfile.read(4)
    wimflags = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # WIM compressed block size, can be 0, but most likely will be 32k
    checkbytes = checkfile.read(4)
    wimblocksize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # then the 16 byte WIM GUID
    wimguid = checkfile.read(16)
    unpackedsize += 16

    # the WIM part number. For a single file this should be 1.
    checkbytes = checkfile.read(2)
    wimpartnumber = int.from_bytes(checkbytes, byteorder='little')
    if wimpartnumber != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot unpack multipart WIM'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # the total numbers of WIM parts
    checkbytes = checkfile.read(2)
    totalwimparts = int.from_bytes(checkbytes, byteorder='little')
    if totalwimparts != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot unpack multipart WIM'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # the image count
    checkbytes = checkfile.read(4)
    wimimagecount = int.from_bytes(checkbytes, byteorder='little')
    if wimimagecount != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot unpack multipart WIM'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the resources offset table are stored
    # in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    reshdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    reshdrflags = reshdrflagssize >> 56

    # lower 7 bytes are the size
    reshdrsize = reshdrflagssize & 72057594037927935
    unpackedsize += 8

    # then the offset of the resource
    checkbytes = checkfile.read(8)
    resourceoffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + resourceoffset + reshdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # then the original size of the resource
    checkbytes = checkfile.read(8)
    resourceorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    # the XML data is also stored in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    xmlhdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    xmlhdrflags = xmlhdrflagssize >> 56

    # lower 7 bytes are the size
    xmlhdrsize = xmlhdrflagssize & 72057594037927935
    unpackedsize += 8

    # then the offset of the xml
    checkbytes = checkfile.read(8)
    xmloffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + xmloffset + xmlhdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # then the original size of the XML
    checkbytes = checkfile.read(8)
    xmlorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    # any boot information is also stored
    # in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    boothdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    boothdrflags = boothdrflagssize >> 56

    # lower 7 bytes are the size
    boothdrsize = boothdrflagssize & 72057594037927935
    unpackedsize += 8

    # then the offset of the boot data
    checkbytes = checkfile.read(8)
    bootoffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + bootoffset + boothdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # then the original size of the boot data
    checkbytes = checkfile.read(8)
    bootorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    # the boot index
    checkbytes = checkfile.read(4)
    bootindex = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # the integrity table is also stored
    # in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    integrityhdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    integrityhdrflags = integrityhdrflagssize >> 56

    # lower 7 bytes are the size
    integrityhdrsize = integrityhdrflagssize & 72057594037927935
    unpackedsize += 8

    # then the offset of the boot data
    checkbytes = checkfile.read(8)
    integrityoffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + integrityoffset + integrityhdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # then the original size of the boot data
    checkbytes = checkfile.read(8)
    bootorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    # record the maximum offset
    maxoffset = offset + max(unpackedsize, integrityoffset + integrityhdrsize, bootoffset + boothdrsize, xmloffset + xmlhdrsize, resourceoffset + reshdrsize)
    unpackedsize = maxoffset - offset

    # extract and store the XML, as it might come in handy later
    wimxml = None
    if xmlhdrsize != 0:
        checkfile.seek(offset + xmloffset)
        checkbytes = checkfile.read(xmlhdrsize)
        try:
            wimxml = checkbytes.decode('utf_16_le')
        except:
            pass

    # extra sanity check: parse the XML if any was extracted
    if wimxml is not None:
        try:
            defusedxml.minidom.parseString(wimxml)
        except:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid XML stored in WIM'}
            return {'status': False, 'error': unpackingerror}

    if shutil.which('7z') is None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': '7z program not found'}
        return {'status': False, 'error': unpackingerror}

    havetmpfile = False
    if not (offset == 0 and filesize == unpackedsize):
        temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir_full, '-y', 'x', temporaryfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if offset == 0 and filesize == unpackedsize:
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir_full, '-y', 'x', filename_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid WIM file'}
        return {'status': False, 'error': unpackingerror}

    dirwalk = os.walk(unpackdir_full)
    for direntries in dirwalk:
        # make sure all subdirectories and files can be accessed
        for subdir in direntries[1]:
            subdirname = os.path.join(direntries[0], subdir)
            if not os.path.islink(subdirname):
                os.chmod(subdirname, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        for fn in direntries[2]:
            fullfilename = os.path.join(direntries[0], fn)
            relfilename = scanenvironment.rel_unpack_path(fullfilename)
            unpackedfilesandlabels.append((relfilename, []))

    if not havetmpfile:
        labels.append('mswim')
        labels.append('compressed')
        labels.append('archive')

    # cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# /usr/share/magic
unpack_wim.signatures = {'mswim': b'MSWIM\x00\x00\x00'}
unpack_wim.minimum_size = 208


# The RPM format is described as part of the Linux Standards Base:
#
# http://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/pkgformat.html
#
# There are references in the code to the right section in the LSB.
#
# This code can detect, but not unpack, delta RPMs:
#
# https://github.com/rpm-software-management/deltarpm/blob/master/README
def unpack_rpm(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack a RPM file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    # the RPM lead is 96 bytes (section 22.2.1)
    if filesize - offset < 96:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 96 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then process the RPM lead. Many of these values are duplicated
    # in the header later in the file.

    # read the major version. The standard version is 3. There have
    # also been files with major 4.
    checkbytes = checkfile.read(1)
    majorversion = ord(checkbytes)
    if majorversion > 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not a valid RPM major version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    checkbytes = checkfile.read(1)
    minorversion = ord(checkbytes)
    unpackedsize += 1

    # then read the type
    checkbytes = checkfile.read(2)
    rpmtype = int.from_bytes(checkbytes, byteorder='big')
    if rpmtype == 0:
        issourcerpm = False
    elif rpmtype == 1:
        issourcerpm = True
    else:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not a valid RPM type'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # read the architecture
    checkbytes = checkfile.read(2)
    unpackedsize += 2

    # the name of the file, should be NUL terminated
    checkbytes = checkfile.read(66)
    if b'\x00' not in checkbytes:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'name not NUL terminated'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 66

    # osnum: "shall be 1"
    checkbytes = checkfile.read(2)
    osnum = int.from_bytes(checkbytes, byteorder='big')
    if osnum != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'osnum not 1'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # signature type: "shall be 5"
    checkbytes = checkfile.read(2)
    signaturetype = int.from_bytes(checkbytes, byteorder='big')
    if signaturetype != 5:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'signature type not 5'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # skip over the 'reserved space'
    checkfile.seek(16, os.SEEK_CUR)
    unpackedsize += 16

    # signature, in header format (section 22.2.2 and 22.2.3)
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for signature'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'\x8e\xad\xe8\x01':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong magic for signature'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # reserved space
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for signature reserved space'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'\x00\x00\x00\x00':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'incorrect values for signature rserved space'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # number of index records, should be at least 1
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for signature index record count'}
        return {'status': False, 'error': unpackingerror}
    signatureindexrecordcount = int.from_bytes(checkbytes, byteorder='big')
    if signatureindexrecordcount < 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for signature index record count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the size of the storage area for the data pointed to by
    # the index records
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for index record size'}
        return {'status': False, 'error': unpackingerror}
    signaturehsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # process all the index records (section 22.2.2.2)
    for i in range(0, signatureindexrecordcount):
        # first the tag
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record tag'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # then the type
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record type'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # then the offset
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record offset'}
            return {'status': False, 'error': unpackingerror}
        indexoffset = int.from_bytes(checkbytes, byteorder='big')
        if indexoffset > signaturehsize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid index record offset'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # the size of the record
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index count'}
            return {'status': False, 'error': unpackingerror}
        indexcount = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

    # then the signature size
    if checkfile.tell() + signaturehsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for signature storage area'}
        return {'status': False, 'error': unpackingerror}

    checkfile.seek(signaturehsize, os.SEEK_CUR)
    unpackedsize += signaturehsize

    # then pad on an 8 byte boundary
    if unpackedsize % 8 != 0:
        checkfile.seek(8 - unpackedsize % 8, os.SEEK_CUR)
        unpackedsize += 8 - unpackedsize % 8

    # Next is the Header, which is identical to the Signature
    # (section 22.2.2 and 22.2.3)
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'\x8e\xad\xe8\x01':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong magic for header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # reserved space
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header reserved space'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'\x00\x00\x00\x00':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'incorrect values for header rserved space'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # number of index records, should be at least 1
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header index record count'}
        return {'status': False, 'error': unpackingerror}
    headerindexrecordcount = int.from_bytes(checkbytes, byteorder='big')
    if headerindexrecordcount < 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for header index record count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # the size of the storage area for the data pointed
    # to by the index records
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for index record size'}
        return {'status': False, 'error': unpackingerror}
    headerhsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # keep a list of tags to offsets and sizes
    headertagtooffsets = {}

    # process all the index records (section 22.2.2.2)
    for i in range(0, headerindexrecordcount):
        # first the tag
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record tag'}
            return {'status': False, 'error': unpackingerror}
        headertag = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        # then the type
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record type'}
            return {'status': False, 'error': unpackingerror}
        headertype = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        # then the offset
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record offset'}
            return {'status': False, 'error': unpackingerror}
        indexoffset = int.from_bytes(checkbytes, byteorder='big')
        if indexoffset > headerhsize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid index record offset'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # the size of the record
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index count'}
            return {'status': False, 'error': unpackingerror}
        indexcount = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        if headertag not in headertagtooffsets:
            headertagtooffsets[headertag] = (indexoffset, indexcount, headertype)

    # then the header size
    if checkfile.tell() + headerhsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header storage area'}
        return {'status': False, 'error': unpackingerror}

    # first store the old offset
    oldoffset = checkfile.tell()

    tagstoresults = {}

    # and inspect each of the tags, which are not necessarily ordered
    for i in headertagtooffsets:
        checkfile.seek(oldoffset)
        (tagoffset, tagcount, tagtype) = headertagtooffsets[i]
        checkfile.seek(tagoffset, os.SEEK_CUR)

        # store results for tags, for now for strings only
        tagresults = []

        # depending on the type a different size has to be read
        # (section 22.2.2.2.1)
        for c in range(0, tagcount):
            # char
            if tagtype == 1:
                checkbytes = checkfile.read(1)
            # int8
            elif tagtype == 2:
                checkbytes = checkfile.read(1)
            # int16
            elif tagtype == 3:
                # TODO: alignment
                checkbytes = checkfile.read(2)
            # int32
            elif tagtype == 4:
                # TODO: alignment
                checkbytes = checkfile.read(4)
            # reserved
            elif tagtype == 5:
                pass
            # string
            elif tagtype == 6:
                tagstr = b''
                while True:
                    checkbytes = checkfile.read(1)
                    if checkbytes == b'\x00':
                        break
                    tagstr += checkbytes
                tagresults.append(tagstr)
            # bin
            elif tagtype == 7:
                checkbytes = checkfile.read(1)
                pass
            # string array
            elif tagtype == 8:
                tagstr = b''
                while True:
                    checkbytes = checkfile.read(1)
                    if checkbytes == b'\x00':
                        break
                    tagstr += checkbytes
                tagresults.append(tagstr)
            # i18n type
            elif tagtype == 9:
                tagstr = b''
                while True:
                    checkbytes = checkfile.read(1)
                    if checkbytes == b'\x00':
                        break
                    tagstr += checkbytes
                tagresults.append(tagstr)
        checkbytes = checkfile.read(tagcount)
        if len(tagresults) != 0:
            tagstoresults[i] = tagresults

    # then seek back to the old offset
    checkfile.seek(oldoffset)

    # then jump over the header data
    checkfile.seek(headerhsize, os.SEEK_CUR)
    unpackedsize += signaturehsize

    # then unpack the file. This depends on the compressor and the
    # payload format.  The default compressor is either gzip or XZ
    # (on Fedora). Other supported compressors are bzip2, LZMA and
    # zstd (recent addition).
    #
    # 1125 is the tag for the compressor.
    if 1125 not in tagstoresults:
        # gzip by default
        unpackresult = unpack_gzip(fileresult, scanenvironment, checkfile.tell(), unpackdir)
    else:
        if len(tagstoresults[1125]) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'duplicate compressor defined'}
            return {'status': False, 'error': unpackingerror}
        compressor = tagstoresults[1125][0]
        if compressor == b'gzip':
            unpackresult = unpack_gzip(fileresult, scanenvironment, checkfile.tell(), unpackdir)
        elif compressor == b'bzip2':
            unpackresult = unpack_bzip2(fileresult, scanenvironment, checkfile.tell(), unpackdir)
        elif compressor == b'xz':
            unpackresult = unpack_xz(fileresult, scanenvironment, checkfile.tell(), unpackdir)
        elif compressor == b'lzma':
            unpackresult = unpack_lzma(fileresult, scanenvironment, checkfile.tell(), unpackdir)
        elif compressor == b'zstd':
            unpackresult = unpack_zstd(fileresult, scanenvironment, checkfile.tell(), unpackdir)
        else:
            # gzip is default
            unpackresult = unpack_gzip(fileresult, scanenvironment, checkfile.tell(), unpackdir)

    if not unpackresult['status']:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'could not decompress payload'}
        return {'status': False, 'error': unpackingerror}

    rpmunpacksize = unpackresult['length']
    rpmunpackfiles = unpackresult['filesandlabels']
    if len(rpmunpackfiles) != 1:
        # this should never happen
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'could not decompress payload'}
        return {'status': False, 'error': unpackingerror}

    payload = None
    payloadfile = rpmunpackfiles[0][0]
    payloadfile_full = scanenvironment.unpack_path(payloadfile)

    # 1124 is the payload. Only 'cpio' can be unpacked at the moment.
    if 1124 in tagstoresults:
        if len(tagstoresults[1124]) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'duplicate payload defined'}
            return {'status': False, 'error': unpackingerror}

        payload = tagstoresults[1124][0]
        if payload == b'cpio':
            # first move the payload file to a different location
            # to avoid any potential name clashes
            payloadsize = payloadfile_full.stat().st_size
            payloaddir = pathlib.Path(tempfile.mkdtemp(dir=scanenvironment.temporarydirectory))
            shutil.move(str(payloadfile_full), payloaddir)

            # create a file result object and pass it to the CPIO unpacker
            fr = FileResult(fileresult,
                    payloaddir / os.path.basename(payloadfile),
                    set([]))
            fr.set_filesize(payloadsize)

            # assuming that the CPIO data is always in "new ascii" format
            cpio_parser = cpio_unpack.CpioNewAsciiUnpackParser(fr, scanenvironment, unpackdir, 0)
            try:
                cpio_parser.open()
                unpackresult = cpio_parser.parse_and_unpack()
            except UnpackParserException as e:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'could not unpack CPIO payload'}
            finally:
                cpio_parser.close()

            shutil.rmtree(payloaddir)

            # walk the results and add them. This is a bit ugly as
            # the data is already in the right format, but it has to be
            # reworked to the old format.
            for i in unpackresult.unpacked_files:
                unpackedfilesandlabels.append((i.filename, i.labels))
        elif payload == b'drpm':
            payloadfile_rel = scanenvironment.rel_unpack_path(payloadfile)
            unpackedfilesandlabels.append((payloadfile_rel, ['delta rpm data']))

    unpackedsize = checkfile.tell() + rpmunpacksize - offset

    if offset == 0 and unpackedsize == filesize:
        labels.append('rpm')
        if issourcerpm:
            labels.append('srpm')
        if payload == b'drpm':
            labels.append('drpm')

    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_rpm.signatures = {'rpm': b'\xed\xab\xee\xdb'}
unpack_rpm.minimum_size = 96


# zstd
# https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
def unpack_zstd(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack zstd compressed data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if shutil.which('zstd') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'zstd program not found'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename_full, 'rb')
    # skip the magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then read the frame header descriptor as it might indicate
    # whether or not there is a size field.
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for zstd frame header'}
        return {'status': False, 'error': unpackingerror}

    if ord(checkbytes) & 32 == 0:
        single_segment = False
    else:
        single_segment = True

    # process the frame header descriptor to see how big the
    # frame header is.
    frame_content_size_flag = ord(checkbytes) >> 6
    if frame_content_size_flag == 3:
        fcs_field_size = 8
    elif frame_content_size_flag == 2:
        fcs_field_size = 4
    elif frame_content_size_flag == 1:
        fcs_field_size = 2
    else:
        # now it depends on the single_segment_flag
        if not single_segment:
            fcs_field_size = 0
        else:
            fcs_field_size = 1

    # reserved bit MUST 0
    if ord(checkbytes) & 8 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved bit set'}
        return {'status': False, 'error': unpackingerror}

    # content checksum flag
    content_checksum_set = False
    if ord(checkbytes) & 4 == 4:
        content_checksum_set = True

    # then did_field_size
    if ord(checkbytes) & 3 == 0:
        did_field_size = 0
    elif ord(checkbytes) & 3 == 1:
        did_field_size = 1
    elif ord(checkbytes) & 3 == 2:
        did_field_size = 2
    elif ord(checkbytes) & 3 == 3:
        did_field_size = 4

    # check to see if the window descriptor is present
    if not single_segment:
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for window descriptor'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    # then read the dictionary
    if did_field_size != 0:
        checkbytes = checkfile.read(did_field_size)
        if len(checkbytes) != did_field_size:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for dictionary'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += did_field_size

    if fcs_field_size != 0:
        checkbytes = checkfile.read(fcs_field_size)
        if len(checkbytes) != fcs_field_size:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for frame content size'}
            return {'status': False, 'error': unpackingerror}
        uncompressed_size = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += fcs_field_size

    # then the blocks: each block starts with 3 bytes
    while True:
        lastblock = False
        checkbytes = checkfile.read(3)
        if len(checkbytes) != 3:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for frame'}
            return {'status': False, 'error': unpackingerror}
        # first check if it is the last block
        if checkbytes[0] & 1 == 1:
            lastblock = True

        blocksize = int.from_bytes(checkbytes, byteorder='little') >> 3
        blocktype = int.from_bytes(checkbytes, byteorder='little') >> 1 & 0b11

        # RLE blocks are always size 1, as block size means
        # something else in that context.
        if blocktype == 1:
            blocksize = 1

        if checkfile.tell() + blocksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for frame'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(blocksize, os.SEEK_CUR)
        if lastblock:
            break

    if content_checksum_set:
        # lower 32 bytes of xxHash checksum of the original
        # decompressed data
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for checksum'}
            return {'status': False, 'error': unpackingerror}

    unpackedsize = checkfile.tell() - offset

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # zstd does not record the name of the file that was
    # compressed, so guess, or just set a name.
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        if filename_full.suffix.lower() == '.zst':
            outfile_rel = os.path.join(unpackdir, filename_full.stem)
        else:
            outfile_rel = os.path.join(unpackdir, "unpacked-by-zstd")
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        p = subprocess.Popen(['zstd', '-d', '-o', outfile_full, filename_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid zstd'}
            return {'status': False, 'error': unpackingerror}
        if fcs_field_size != 0:
            if uncompressed_size != os.stat(outfile_full).st_size:
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid checksum'}
                return {'status': False, 'error': unpackingerror}
        labels.append('zstd')
        labels.append('compressed')
    else:
        tmpfilename = os.path.join(unpackdir, "unpacked-by-zstd.zst")
        tmpfile_full = scanenvironment.unpack_path(tmpfilename)
        tmpfile = open(tmpfile_full, 'wb')
        os.sendfile(tmpfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        tmpfile.close()
        checkfile.close()
        outfile_rel = tmpfilename[:-4]
        outfile_full = scanenvironment.unpack_path(outfile_rel)
        p = subprocess.Popen(['zstd', '-d', '--rm', '-o', outfile_full, tmpfile_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            os.unlink(tmpfile_full)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid zstd'}
            return {'status': False, 'error': unpackingerror}
        if fcs_field_size != 0:
            if uncompressed_size != os.stat(outfile_full).st_size:
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid checksum'}
                return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfile_rel, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# /usr/share/magic
unpack_zstd.signatures = {'zstd_08': b'\x28\xb5\x2f\xfd'}
unpack_zstd.pretty = 'zstd'


# https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
# uses https://pypi.org/project/lz4/
def unpack_lz4(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack LZ4 compressed data.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    outfile_rel = os.path.join(unpackdir, "unpacked-from-lz4")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')

    # first create a decompressor object
    decompressor = lz4.frame.create_decompression_context()

    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    readsize = 1000000
    checkbytes = checkfile.read(readsize)

    seeneof = False
    while checkbytes != b'':
        try:
            uncompressresults = lz4.frame.decompress_chunk(decompressor, checkbytes)
            outfile.write(uncompressresults[0])
            outfile.flush()
        except:
            checkfile.close()
            outfile.close()
            os.unlink(outfile_full)
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'LZ4 unpacking error'}
            return {'status': False, 'error': unpackingerror}

        unpackedsize += uncompressresults[1]

        # end of the data/LZ4 frame footer
        if uncompressresults[2]:
            outfile.close()
            seeneof = True
            break
        checkbytes = checkfile.read(readsize)

    outfile.close()
    checkfile.close()

    if not seeneof:
        os.unlink(outfile_full)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data incomplete'}
        return {'status': False, 'error': unpackingerror}

    # in case the whole file name is the lz4 file and the extension
    # is .lz4 rename the file.
    if offset == 0 and unpackedsize == filesize:
        labels.append('compressed')
        labels.append('lz4')
        if filename_full.suffix.lower() == '.lz4':
            newoutfile_rel = os.path.join(unpackdir, filename_full.stem)
            newoutfile_full = scanenvironment.unpack_path(newoutfile_rel)
            shutil.move(outfile_full, newoutfile_full)
            outfile_rel = newoutfile_rel
    unpackedfilesandlabels.append((outfile_rel, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# https://github.com/lz4/lz4/blob/master/doc/lz4_Frame_format.md
unpack_lz4.signatures = {'lz4': b'\x04\x22\x4d\x18'}


# There are a few variants of XML. The first one is the "regular"
# one, which is documented at:
# https://www.w3.org/TR/2008/REC-xml-20081126/
#
# Android has a "binary XML", where the XML data has been translated
# into a binary file. This one will eventually be covered by
# bangandroid.unpack_android_resource()
def unpack_xml(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a XML file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # first check if it is and Android XML
    checkfile = open(filename_full, 'rb')
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    if checkbytes == b'\x03\x00\x08\x00':
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Android binary XML not supported'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('xmllint') is None:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'xmllint program not found'}
        return {'status': False, 'error': unpackingerror}

    # XML files sometimes start with a Byte Order Mark
    # https://en.wikipedia.org/wiki/Byte_order_mark
    # XML specification, section F.1
    if checkbytes[0:3] == b'\xef\xbb\xbf':
        unpackedsize += 3
        # rewind one byte, as only three bytes were consumed
        checkfile.seek(-1, os.SEEK_CUR)
    else:
        # else reset to the beginning
        checkfile.seek(offset)

    # White space is defined in the XML specification (section 2.3)
    # and can appear before the processing instruction (see section 2.4)
    # A document has to start with a processing instruction (section 2.6)
    while True:
        checkbytes = checkfile.read(1)
        if checkbytes == b'':
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid character at start of XML file'}
            return {'status': False, 'error': unpackingerror}
        if checkbytes not in [b' ', b'\n', b'\r', b'\t', b'<']:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid character at start of XML file'}
            return {'status': False, 'error': unpackingerror}

        # check to see if the start of the XML data is found. If not,
        # it's white space, so read another character to see if there
        # is more whitespace.
        if checkbytes == b'<':
            # a processing instruction (section 2.6) might follow.
            # The first one should start with "<?xml" (case insensitive)
            checkbytes = checkfile.read(1)
            if checkbytes[0] == b'?':
                if checkbytes.lower() != b'?xml':
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid processing instruction at start of file'}
                    return {'status': False, 'error': unpackingerror}
            break

    checkfile.close()

    # now run xmllint as a sanity check. By default xmllint tries to
    # resolve external entities, so this should be prevented by
    # supplying "--nonet"
    p = subprocess.Popen(['xmllint', '--noout', "--nonet", filename_full],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'xmllint cannot parse file'}
        return {'status': False, 'error': unpackingerror}

    # whole file is XML
    labels.append('xml')
    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_xml.extensions = ['.xml', '.xsd', '.ncx', '.opf', '.svg']


# Uses the description of the Java class file format as described here:
#
# https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html
# TODO: many more checks for valid pointers into the constant pool
def unpack_java_class(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a Java class file.'''
    # a couple of constants. Same names as in the Java class
    # documentation from Oracle.
    CONSTANT_Class = 7
    CONSTANT_Fieldref = 9
    CONSTANT_Methodref = 10
    CONSTANT_InterfaceMethodref = 11
    CONSTANT_String = 8
    CONSTANT_Integer = 3
    CONSTANT_Float = 4
    CONSTANT_Long = 5
    CONSTANT_Double = 6
    CONSTANT_NameAndType = 12
    CONSTANT_Utf8 = 1
    CONSTANT_MethodHandle = 15
    CONSTANT_MethodType = 16
    CONSTANT_InvokeDynamic = 18

    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # store the results for Java:
    # * methods
    # * fields
    # * source file name
    # * class name
    # * strings
    javaresults = {}

    # The minimal size for a valid Java class file is 24 bytes: magic
    # (4 bytes) plus 2 bytes for minor_version, major_version,
    # constant_pool_count access_flags, this_class, super_class,
    # interfaces_count, fields_count, methods_count and attributes_count
    if filesize - offset < 24:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename_full, 'rb')

    # skip over the magic header
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then skip 4 bytes (major + minor versions)
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # Then read two bytes (constant pool count)
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for constant pool'}
        return {'status': False, 'error': unpackingerror}
    constant_pool_count = int.from_bytes(checkbytes, byteorder='big')
    if constant_pool_count == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'empty constant pool'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    islongordouble = False
    constant_pool = {}

    # a mapping of classes to corresponding entries in the constant
    # pool section 4.4.1
    class_table = {}

    string_table = {}

    # read the constants. Many of these have pointers back into the
    # constant_pool for names (methods, signatures, etc.).
    for i in range(1, constant_pool_count):
        if islongordouble:
            islongordouble = False
            continue
        # first read one byte, which is the constant "tag",
        # section 4.4 of specification
        tagbyte = checkfile.read(1)
        if len(tagbyte) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no constant pool tag'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
        tag = ord(tagbyte)
        # how much data is then stored per constant type depends
        # on the type
        if tag == CONSTANT_Class:
            # section 4.4.1
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no name_index'}
                return {'status': False, 'error': unpackingerror}
            class_table[i] = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 2
        elif tag in [CONSTANT_Fieldref, CONSTANT_Methodref, CONSTANT_InterfaceMethodref]:
            # section 4.4.2
            # class index
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no class_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            class_index = int.from_bytes(checkbytes, byteorder='big')

            # name and type index
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no name_and_type_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            name_type_index = int.from_bytes(checkbytes, byteorder='big')
            constant_pool[i] = (class_index, name_type_index)
        elif tag == CONSTANT_String:
            # section 4.4.3
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no string_index'}
                return {'status': False, 'error': unpackingerror}
            string_table[i] = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 2
        elif tag in [CONSTANT_Integer, CONSTANT_Float]:
            # section 4.4.4
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no integer/float bytes'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4
        elif tag in [CONSTANT_Long, CONSTANT_Double]:
            # section 4.4.5
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no high_bytes'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no low_bytes'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4
            # longs and doubles take two entries in the constant pool
            # so one entry needs to be skipped according to section 4.4.5
            islongordouble = True
        elif tag == CONSTANT_NameAndType:
            # section 4.4.6
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no name_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no descriptor_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
        elif tag == CONSTANT_Utf8:
            # section 4.4.7
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no utf8 length'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            utf8len = int.from_bytes(checkbytes, byteorder='big')
            utf8bytes = checkfile.read(utf8len)
            # Caveat: Java uses its own "modified UTF-8", as described
            # in 4.4.7.
            try:
                constant_pool[i] = mutf8.decode_modified_utf8(utf8bytes)
            except UnicodeDecodeError:
                # the upstream mutf8 library has an error and not everything
                # is translated correctly.
                constant_pool[i] = utf8bytes
            if len(utf8bytes) != utf8len:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough utf8 bytes (%d needed)' % utf8len}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += utf8len
        elif tag == CONSTANT_MethodHandle:
            # section 4.4.8
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no reference_kind'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 1
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no reference_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
        elif tag == CONSTANT_MethodType:
            # section 4.4.9
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no descriptor_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
        elif tag == CONSTANT_InvokeDynamic:
            # section 4.4.10
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no bootstrap_method_attr_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no name_and_type_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
    # end of the constant pool reached

    # sanity check: verify all the class objects have valid pointers
    # to valid indexes in the constant pool
    for c in class_table:
        if class_table[c] not in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'class info object does not have valid pointer into constant pool'}
            return {'status': False, 'error': unpackingerror}

    javaresults['strings'] = []

    for s in string_table:
        if string_table[s] not in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'string object does not have valid pointer into constant pool'}
            return {'status': False, 'error': unpackingerror}
        javaresults['strings'].append(constant_pool[string_table[s]])

    # read the access flags
    access_flags = checkfile.read(2)
    if len(access_flags) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no access_flags'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # this_class
    # This points to an index in the constant pool table, which should
    # be a class file (which here are kept in class_table instead).
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no this_class'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    this_class_index = int.from_bytes(checkbytes, byteorder='big')
    if this_class_index not in class_table:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no valid pointer into class table'}
        return {'status': False, 'error': unpackingerror}

    # super_class
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no super_class'}
        return {'status': False, 'error': unpackingerror}
    super_class_index = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    # interfaces_count
    interfaces_count_bytes = checkfile.read(2)
    if len(interfaces_count_bytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no interfaces_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    interfaces_count = int.from_bytes(interfaces_count_bytes, byteorder='big')

    # read the interfaces
    for i in range(0, interfaces_count):
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no interface'}
            return {'status': False, 'error': unpackingerror}

        # The interface should point to a valid class
        interface_index = int.from_bytes(checkbytes, byteorder='big')
        if interface_index not in class_table:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid interface in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

    # fields_count
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no fields_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    fields_count = int.from_bytes(checkbytes, byteorder='big')

    javaresults['fields'] = []

    # read the fields, section 4.5
    for i in range(0, fields_count):
        # access flags
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for access_flags'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        # field name index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for name index'}
            return {'status': False, 'error': unpackingerror}
        field_name_index = int.from_bytes(checkbytes, byteorder='big')

        # field_name_index has to be a valid entry in the constant pool
        if field_name_index not in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid name_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        javaresults['fields'].append(constant_pool[field_name_index])
        unpackedsize += 2

        # field descriptor index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for name index'}
            return {'status': False, 'error': unpackingerror}
        field_descriptor_index = int.from_bytes(checkbytes, byteorder='big')

        # field_descriptor_index has to be a valid entry in
        # the constant pool
        if field_descriptor_index not in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid descriptor_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        # finally the attributes count
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no field attributes_count'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2
        attributes_count = int.from_bytes(checkbytes, byteorder='big')

        for a in range(0, attributes_count):
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough field attributes'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough field attributes'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4
            attribute_info_length = int.from_bytes(checkbytes, byteorder='big')

            checkbytes = checkfile.read(attribute_info_length)
            if len(checkbytes) != attribute_info_length:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'field attribute length incorrect'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += attribute_info_length

    # methods_count
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no methods_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    methods_count = int.from_bytes(checkbytes, byteorder='big')

    javaresults['methods'] = []

    # read the methods, section 4.6
    for i in range(0, methods_count):
        # access flags
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no methods'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        # name index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no methods'}
            return {'status': False, 'error': unpackingerror}

        method_name_index = int.from_bytes(checkbytes, byteorder='big')

        # method_name_index has to be a valid entry in the constant pool
        if method_name_index not in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid name_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2
        javaresults['methods'].append(constant_pool[method_name_index])

        # descriptor index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no methods'}
            return {'status': False, 'error': unpackingerror}

        method_descriptor_index = int.from_bytes(checkbytes, byteorder='big')

        # method_descriptor_index has to be a valid entry in the constant pool
        if method_descriptor_index not in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid descriptor_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'no method attributes_count'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        attributes_count = int.from_bytes(checkbytes, byteorder='big')
        for a in range(0, attributes_count):
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no method attributes'}
                return {'status': False, 'error': unpackingerror}
            attribute_name_index = int.from_bytes(checkbytes, byteorder='big')

            # attribute_name_index has to be a valid entry
            # in the constant pool
            if attribute_name_index not in constant_pool:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not a valid name_index in constant pool'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            # length of the attribute
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough method attributes'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4
            attribute_info_length = int.from_bytes(checkbytes, byteorder='big')

            checkbytes = checkfile.read(attribute_info_length)
            if len(checkbytes) != attribute_info_length:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'method attribute length incorrect'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += attribute_info_length

    # attributes_count
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no attributes_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    attributes_count = int.from_bytes(checkbytes, byteorder='big')

    # read the attributes, section 4.7
    for i in range(0, attributes_count):
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough attributes'}
            return {'status': False, 'error': unpackingerror}

        attribute_name_index = int.from_bytes(checkbytes, byteorder='big')

        # attribute_name_index has to be a valid entry in the constant pool
        if attribute_name_index not in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid name_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        # length of the attribute
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough attributes'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        attribute_info_length = int.from_bytes(checkbytes, byteorder='big')
        checkbytes = checkfile.read(attribute_info_length)
        if len(checkbytes) != attribute_info_length:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'attribute length incorrect'}
            return {'status': False, 'error': unpackingerror}
        if constant_pool[attribute_name_index] == 'SourceFile':
            sourcefileindex = int.from_bytes(checkbytes, byteorder='big')
            if sourcefileindex not in constant_pool:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid index for source file attribute'}
                return {'status': False, 'error': unpackingerror}
            javaresults['sourcefile'] = constant_pool[sourcefileindex]
        unpackedsize += attribute_info_length

    # sometimes there is a full path inside the class file
    # This can be found by first finding the right class
    # in the constant pool and then using this index to
    # find the corresponding name in the constant pool.
    if this_class_index in class_table:
        if class_table[this_class_index] in constant_pool:
            classname = constant_pool[class_table[this_class_index]]
            javaresults['classname'] = classname

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('java class')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels,
                'metadata': javaresults}

    # else carve the file. The name of the class file can often
    # be derived from the class data itself.
    if this_class_index in class_table:
        if class_table[this_class_index] in constant_pool:
            classname = os.path.basename(constant_pool[class_table[this_class_index]])
            # sometimes the name ends in .class, but sometimes
            # it doesn't, so add it.
            if not classname.endswith('.class'):
                classname += '.class'
        else:
            # name could not be found in the constant pool
            # so just give it a name
            classname = "unpacked.class"
    else:
        # It is anonymous, so just give it a name
        classname = "unpacked.class"

    outfile_rel = os.path.join(unpackdir, classname)
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['java class', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels, 'metadata': javaresults}

unpack_java_class.signatures = {'javaclass': b'\xca\xfe\xba\xbe'}
unpack_java_class.minimum_size = 24


# method to see if a file has one or more certificates in various formats
# The SSL certificate formats themselves are defined in for example:
# * X.690 - https://en.wikipedia.org/wiki/X.690
# * X.509 - https://en.wikipedia.org/wiki/X.509
def unpack_certificate(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a certificate file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    dataunpacked = False

    # For reasons unknown pyOpenSSL sometimes barfs on certs from
    # Android, so use an external tool (for now).
    if shutil.which('openssl') is None:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'openssl program not found'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0:
        certres = extract_certificate(filename_full, scanenvironment, offset)
        if certres['status']:
            labels += certres['labels']
            labels = list(set(labels))
            return {'status': True, 'length': filesize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    # open the file
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(11)
    if checkbytes != b'-----BEGIN ':
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid certificate'}
        return {'status': False, 'error': unpackingerror}

    # rewind and read more data
    checkfile.seek(offset)
    checkbytes = checkfile.read(2048)
    certtype = None
    if b'PRIVATE KEY' in checkbytes:
        certtype = 'key'
        outfile_rel = os.path.join(unpackdir, 'unpacked.key')
    elif b'CERTIFICATE' in checkbytes:
        certtype = 'certificate'
        outfile_rel = os.path.join(unpackdir, 'unpacked.crt')
    else:
        outfile_rel = os.path.join(unpackdir, 'unpacked-certificate')

    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')

    # this is a bit hackish, but hey, it works in most of the cases :-)
    certbuf = checkbytes
    certunpacked = False
    tmplabels = []
    while True:
        endres = certbuf.find(b'-----END')
        if endres != -1:
            if certtype == 'key':
                certendres = certbuf.find(b'KEY-----', endres)
                if certendres != -1:
                    tmplabels.append('private key')
                    outfile.write(certbuf[:certendres+8])
                    certunpacked = True
                    break
            elif certtype == 'certificate':
                certendres = certbuf.find(b'CERTIFICATE-----', endres)
                if certendres != -1:
                    tmplabels.append('certificate')
                    if b' TRUSTED ' in certbuf:
                        tmplabels.append('trusted certificate')
                    outfile.write(certbuf[:certendres+16])
                    certunpacked = True
                    break
            else:
                certendres = certbuf.find(b'-----', endres+1)
                if certendres != -1:
                    tmplabels.append('certificate')
                    outfile.write(certbuf[:certendres+5])
                    certunpacked = True
                    break

        # only printables are allowed, so as soon as a non-printable
        # character is encountered exit. Only check the last bytes
        # that have been read.
        if list(filter(lambda x: chr(x) not in string.printable, checkbytes)) != []:
            break
        checkbytes = checkfile.read(2048)
        if checkbytes == b'':
            break
        certbuf += checkbytes

    outfile.close()
    checkfile.close()

    # as an extra sanity check run it through the unpacker
    certres = extract_certificate(outfile_full, scanenvironment, 0)
    if certres['status']:
        tmplabels += certres['labels']
        tmplabels = list(set(tmplabels))
        tmplabels.append('unpacked')
        outsize = outfile_full.stat().st_size
        unpackedfilesandlabels.append((outfile_rel, tmplabels))
        return {'status': True, 'length': outsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # cleanup
    os.unlink(outfile_full)
    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'not a valid certificate'}
    return {'status': False, 'error': unpackingerror}

unpack_certificate.signatures = {'certificate': b'-----BEGIN '}
unpack_certificate.extensions = ['.rsa', '.pem']
unpack_certificate.pretty = 'certificate'


def extract_certificate(filename_full, scanenvironment, offset):
    '''Helper method to extract certificate files.'''
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    if shutil.which('openssl') is None:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'openssl program not found'}
        return {'status': False, 'error': unpackingerror}

    # First see if a file is in DER format
    p = subprocess.Popen(["openssl", "asn1parse", "-inform", "DER", "-in", filename_full], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode == 0:
        labels.append("certificate")
        labels.append('resource')
        return {'status': True, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # then check if it is a PEM
    p = subprocess.Popen(["openssl", "asn1parse", "-inform", "PEM", "-in", filename_full], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode == 0:
        # there could be several certificates or keys
        # inside the file.
        # TODO: split into certificates and private keys
        # The openssl program does also accept binary crap,
        # so add some extra checks.
        isopened = False
        try:
            checkfile = open(filename_full, 'r')
            isopened = True
            for checkline in checkfile:
                # then check if this is perhaps a private key
                if "PRIVATE KEY" in checkline:
                    labels.append('private key')
                # or a certificate
                if "BEGIN CERTIFICATE" in checkline:
                    labels.append("certificate")
                # or a trusted certificate
                if "TRUSTED CERTIFICATE" in checkline:
                    labels.append("trusted certificate")
            checkfile.close()
        except UnicodeDecodeError:
            if isopened:
                checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not a valid certificate'}
            return {'status': False, 'error': unpackingerror}
        labels.append("text")
        labels.append('resource')
        return {'status': True, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else fail
    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'not a valid certificate'}
    return {'status': False, 'error': unpackingerror}


# https://github.com/git/git/blob/master/Documentation/technical/index-format.txt
def unpack_git_index(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a Git index file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # each Git index file starts with a 12 byte header
    if filesize - offset < 12:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip over the header
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # then the version number. Currently only 2, 3 and 4 are supported.
    checkbytes = checkfile.read(4)
    gitindexversion = int.from_bytes(checkbytes, byteorder='big')
    #if gitindexversion < 2 and gitindexversion > 4:
    # only support version 2 now
    if gitindexversion != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported Git index version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # then the number of index entries
    checkbytes = checkfile.read(4)
    gitentries = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # then the entries. There are 10 4 byte entries first
    for n in range(0, gitentries):
        gitentrystart = checkfile.tell()
        if filesize - checkfile.tell() < 40:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for Git entry'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 40
        checkfile.seek(40, os.SEEK_CUR)

        # then a 20 byte SHA1
        if filesize - checkfile.tell() < 20:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for Git entry SHA1'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 20
        checkfile.seek(20, os.SEEK_CUR)

        # then 2 bytes of flags
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for Git entry flags'}
            return {'status': False, 'error': unpackingerror}
        gitentryflags = int.from_bytes(checkbytes, byteorder='big')

        # 12 lower bits of the flags are for the file name length
        filenamelength = (gitentryflags & 0xfff)
        if checkfile.tell() + filenamelength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for file name'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(filenamelength, os.SEEK_CUR)
        unpackedsize += 2 + filenamelength

        # then padding bytes to keep the entry (not the file name!)
        # to a multiple of 8 bytes
        paddingbytesamount = 8 - (checkfile.tell() - gitentrystart) % 8
        if paddingbytesamount != 0:
            if checkfile.tell() + paddingbytesamount > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for entry padding'}
                return {'status': False, 'error': unpackingerror}
            checkfile.seek(paddingbytesamount, os.SEEK_CUR)
            unpackedsize += paddingbytesamount

    knowngitextensions = set([b'TREE', b'REUC', b'link', b'UNTR', b'FSMN'])
    # then the extensions
    while filesize - (offset + unpackedsize) > 20:
        # read four bytes for the extension name
        checkbytes = checkfile.read(4)
        if checkbytes in knowngitextensions:
            pass
        else:
            # check for any unknown extensions
            if checkbytes[0] < ord('A') or checkbytes[0] > ord('Z'):
                # Extension is invalid.
                # first rewind 4 bytes in the file, as other
                # useful data might follow it.
                checkfile.seek(-4, os.SEEK_CUR)
                break
            else:
                # Extension is unknown, but possibly valid.
                # For now just stick to the known extensions.
                # This means that the list of known extensions
                # should be kept up to date to avoid false
                # negatives.
                checkfile.seek(-4, os.SEEK_CUR)
                break
        unpackedsize += 4

        # then the size of the extension
        checkbytes = checkfile.read(4)
        extensionsize = int.from_bytes(checkbytes, byteorder='big')
        if checkfile.tell() + extensionsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for Git extension'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(extensionsize, os.SEEK_CUR)
        unpackedsize += 4 + extensionsize

    # finally check if there is a SHA1
    if filesize - unpackedsize < 20:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for Git index SHA1'}
        return {'status': False, 'error': unpackingerror}

    storedgithash = checkfile.read(20)

    # rewind to the start of the Git index
    checkfile.seek(offset)

    # create a hashing object
    githash = hashlib.new('sha1')

    # read all the unpacked data
    githash.update(checkfile.read(unpackedsize))

    # compare the SHA1 stored with the SHA1 computed
    if githash.digest() != storedgithash:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'incorrect index SHA1'}
        return {'status': False, 'error': unpackingerror}
    checkfile.seek(20, os.SEEK_CUR)
    unpackedsize += 20

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('git index')
        labels.append('resource')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # Carve the image.
    # first reset the file pointer
    checkfile.seek(offset)
    outfile_rel = os.path.join(unpackdir, "index")
    outfile_full = scanenvironment.unpack_path(outfile_rel)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['git index', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# https://github.com/git/git/blob/master/Documentation/technical/index-format.txt
unpack_git_index.signatures = {'git_index': b'DIRC'}
unpack_git_index.minimum_size = 12


def unpack_json(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a JSON file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # open the file
    checkfile = open(filename_full, 'rb')

    # try to read the contents of the file as JSON
    try:
        json.load(checkfile)
    except json.JSONDecodeError as e:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid JSON'}
        return {'status': False, 'error': unpackingerror}
    except UnicodeError as e:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid JSON'}
        return {'status': False, 'error': unpackingerror}
    except RecursionError:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'recursion limit exceeded'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    # whole file is JSON
    unpackedsize = filesize

    labels.append('json')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_json.extensions = ['.json']
unpack_json.pretty = 'json'


# Transform a pack200 file to a JAR file using the unpack200 tool.
# This will not restore the original JAR file, as pack200 performs all kinds
# of optimizations, such as removing redundant classes, and so on.
#
# https://docs.oracle.com/javase/7/docs/technotes/guides/pack200/pack-spec.html
#
# The header format is described in section 5.2
def unpack_pack200(fileresult, scanenvironment, offset, unpackdir):
    '''Convert a pack200 file back into a JAR'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # first check if the unpack200 program is actually there
    if shutil.which('unpack200') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unpack200 program not found'}
        return {'status': False, 'error': unpackingerror}

    # the unpack200 tool only works on whole files. Finding out
    # where the file ends is TODO, but if there is data in front
    # of a valid pack200 file it is not a problem.
    if offset != 0:
        # create a temporary file and copy the data into the
        # temporary file if offset != 0
        checkfile = open(filename_full, 'rb')
        temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, filesize - offset)
        os.fdopen(temporaryfile[0]).close()
        checkfile.close()

    # write unpacked data to a JAR file
    outfile_rel = os.path.join(unpackdir, "unpacked.jar")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # then extract the file
    if offset != 0:
        p = subprocess.Popen(['unpack200', temporaryfile[1], outfile_full],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=unpackdir_full)
    else:
        p = subprocess.Popen(['unpack200', filename_full, outfile_full],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=unpackdir_full)
    (outputmsg, errormsg) = p.communicate()

    if offset != 0:
        os.unlink(temporaryfile[1])

    if p.returncode != 0:
        # try to remove any files that were possibly left behind
        try:
            os.unlink(outfile_full)
        except:
            pass
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid pack200 file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = filesize - offset

    if offset == 0 and unpackedsize == filesize:
        labels.append('pack200')

    unpackedfilesandlabels.append((outfile_rel, []))

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_pack200.signatures = {'pack200': b'\xca\xfe\xd0\x0d'}


# https://wiki.openzim.org/wiki/ZIM_file_format
# https://wiki.openzim.org/wiki/ZIM_File_Example
# Test files: https://wiki.kiwix.org/wiki/Content_in_all_languages
def unpack_zim(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack/verify a ZIM file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # ZIM header is 80 bytes
    if offset + 80 > filesize:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the offset
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)

    unpackedsize += 4

    # first the major version
    checkbytes = checkfile.read(2)
    majorversion = int.from_bytes(checkbytes, byteorder='little')
    # only support version 5 now, as it is easier to parse
    #if majorversion != 5 and majorversion != 6:
    if majorversion != 5:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # minor version
    checkbytes = checkfile.read(2)
    minorversion = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    # zim uuid
    checkbytes = checkfile.read(16)
    unpackedsize += 16

    # articlecount
    checkbytes = checkfile.read(4)
    articlecount = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # clustercount
    checkbytes = checkfile.read(4)
    clustercount = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # urlptrpos
    checkbytes = checkfile.read(8)
    urlptrpos = int.from_bytes(checkbytes, byteorder='little')
    if offset + urlptrpos > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'urlPtrPos outside file'}
        return {'status': False, 'error': unpackingerror}

    # each URL pointer is 8 bytes long
    if offset + urlptrpos + articlecount * 8 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'URL pointer outside file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # titleptrpos
    checkbytes = checkfile.read(8)
    titleptrpos = int.from_bytes(checkbytes, byteorder='little')
    if offset + titleptrpos > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'titlePtrPos outside file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # clusterptrpos
    checkbytes = checkfile.read(8)
    clusterptrpos = int.from_bytes(checkbytes, byteorder='little')
    if offset + clusterptrpos > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'clusterPtrPos outside file'}
        return {'status': False, 'error': unpackingerror}
    # extra sanity check: each cluster pointer is 8 bytes
    if offset + clusterptrpos + clustercount * 8 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'clusterPtrPos outside file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # mimelistpos
    checkbytes = checkfile.read(8)
    mimelistpos = int.from_bytes(checkbytes, byteorder='little')
    if offset + mimelistpos > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'mimeListPos outside file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # main page
    checkbytes = checkfile.read(4)
    mainpage = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # layout page
    checkbytes = checkfile.read(4)
    layoutpage = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # checksumpos
    checkbytes = checkfile.read(8)
    checksumpos = int.from_bytes(checkbytes, byteorder='little')
    if offset + checksumpos > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'checksumPos outside file'}
        return {'status': False, 'error': unpackingerror}
    if offset + checksumpos + 16 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for checksum'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # checksumpos should be the last entry in the file
    if checksumpos != max(urlptrpos, titleptrpos, clusterptrpos, mimelistpos, checksumpos):
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'checksum not last in file'}
        return {'status': False, 'error': unpackingerror}

    # now start processing the articles
    # first jump to the mimelistpos, which should be the same
    # as the current position in the file
    if mimelistpos != unpackedsize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'MIME type list not directly after header'}
        return {'status': False, 'error': unpackingerror}

    # store the MIME types, in order
    articlemimetypes = []

    # now read the mime types, until the empty string is reached
    while True:
        articlemime = b''
        while True:
            checkbytes = checkfile.read(1)
            if checkbytes == b'\x00':
                break
            articlemime += checkbytes
        if articlemime == b'':
            break
        try:
            articlemimetypes.append(articlemime.decode())
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid MIME type'}
            return {'status': False, 'error': unpackingerror}

    # then process the URLs
    checkfile.seek(offset + urlptrpos)
    unpackedsize = urlptrpos

    urlpointers = []

    for i in range(0, articlecount):
        checkbytes = checkfile.read(8)
        urlpointer = int.from_bytes(checkbytes, byteorder='little')
        if offset + urlpointer > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'URL outside file'}
            return {'status': False, 'error': unpackingerror}
        urlpointers.append(urlpointer)
        unpackedsize += 8

    # then the title pointers. These point to indexes of the URL pointers
    checkfile.seek(offset + titleptrpos)
    unpackedsize = titleptrpos

    titlepointers = []

    for i in range(0, articlecount):
        checkbytes = checkfile.read(4)
        titlepointer = int.from_bytes(checkbytes, byteorder='little')
        if titlepointer > articlecount:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'Title pointing to non-existent URL'}
            return {'status': False, 'error': unpackingerror}
        titlepointers.append(titlepointer)
        unpackedsize += 4

    # sanity check for the cluster pointers
    clusterpointers = []
    unpackedsize = clusterptrpos

    # store the offset size and compression per cluster
    clusterinfo = {}

    checkfile.seek(offset + clusterptrpos)
    for i in range(0, clustercount):
        checkbytes = checkfile.read(8)
        clusterpointer = int.from_bytes(checkbytes, byteorder='little')
        if offset + clusterpointer > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'cluster outside file'}
            return {'status': False, 'error': unpackingerror}
        clusterpointers.append(clusterpointer)

        # now check the offset size for each cluster
        # first store the current offset
        oldoffset = checkfile.tell()

        # jump to the cluster
        checkfile.seek(offset + clusterpointer)

        # read the first byte
        checkbytes = checkfile.read(1)
        if checkbytes == b'\x00':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'cluster outside file'}
            return {'status': False, 'error': unpackingerror}

        compressed = False
        if ord(checkbytes) & 15 == 4:
            compressed = True

        offsetsize = 4
        if (ord(checkbytes) >> 4) & 1 == 1:
            offsetsize = 8

        # try to determine the offsets in each cluster
        if not compressed:
            checkbytes = checkfile.read(offsetsize)
            if len(checkbytes) != offsetsize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cluster outside file'}
                return {'status': False, 'error': unpackingerror}

            firstoffset = int.from_bytes(checkbytes, byteorder='little')
            if firstoffset % offsetsize != 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'wrong value for blob offset'}
                return {'status': False, 'error': unpackingerror}
            blobcount = firstoffset//offsetsize
            bloboffsets = [firstoffset]

            for b in range(1, blobcount):
                checkbytes = checkfile.read(offsetsize)
                bloboffset = int.from_bytes(checkbytes, byteorder='little')
                # sanity check
                if offset + clusterpointer + 1 + bloboffset > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'wrong value for blob offset'}
                    return {'status': False, 'error': unpackingerror}
                bloboffsets.append(bloboffset)
            clusterinfo[i] = {'size': offsetsize, 'compressed': compressed,
                              'bloboffsets': bloboffsets}
        else:
            # TODO: this is where things get complex: the data is compressed
            # but the offsets are only valid in the uncompressed data.
            clusterinfo[i] = {'size': offsetsize, 'compressed': compressed}

        # and return to the old offset
        checkfile.seek(oldoffset)
        unpackedsize += 8

    # list of valid name spaces. The documentation omits 'Z',
    # which can be found in libzim/src/search.cpp and is related
    # to Xapian indexes.
    validnamespaces = set(['-', 'A', 'B', 'I', 'J', 'M', 'U', 'V', 'W', 'X', 'Z'])

    # a list of name spaces with actual content, and no metadata
    contentnamespaces = set(['-', 'A', 'I'])

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # then process all the articles
    for i in urlpointers:
        checkfile.seek(offset + i)
        unpackedsize = i

        # there should be at least 12 bytes in each directory entry
        if offset + i + 12 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'directory entry outside file'}
            return {'status': False, 'error': unpackingerror}

        # read the MIME type number
        checkbytes = checkfile.read(2)
        mimetypenumber = int.from_bytes(checkbytes, byteorder='little')

        # first check if an entry is a redirect, link target, or deleted
        if mimetypenumber == 0xffff:
            # redirect
            pass
        elif mimetypenumber in [0xfffe, 0xfffd]:
            # link target (0xfffe)
            # deleted (0xfffd)
            pass
        else:
            # check if the MIME type number is correct
            # numbering starts at 0
            if mimetypenumber >= len(articlemimetypes):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'wrong MIME type number'}
                return {'status': False, 'error': unpackingerror}

        # then the parameterlength
        checkbytes = checkfile.read(1)
        parameterlength = ord(checkbytes)

        # namespace
        checkbytes = checkfile.read(1)
        try:
            namespace = checkbytes.decode()
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong value for namespace'}
            return {'status': False, 'error': unpackingerror}
        if namespace not in validnamespaces:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid namespace'}
            return {'status': False, 'error': unpackingerror}

        # revision
        checkbytes = checkfile.read(4)
        revision = int.from_bytes(checkbytes, byteorder='little')

        # here is where the different entries start to diverge
        if mimetypenumber == 0xffff:
            # redirect
            pass
        elif mimetypenumber in [0xfffe, 0xfffd]:
            # link target (0xfffe)
            # deleted (0xfffd)
            pass
        else:
            # cluster number
            checkbytes = checkfile.read(4)
            clusternumber = int.from_bytes(checkbytes, byteorder='little')

            # check if the MIME type number is correct
            # numbering starts at 0
            if clusternumber >= clustercount:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'wrong cluster number'}
                return {'status': False, 'error': unpackingerror}

            # blob number
            checkbytes = checkfile.read(4)
            blobnumber = int.from_bytes(checkbytes, byteorder='little')

            # URL
            memberurl = b''
            while True:
                checkbytes = checkfile.read(1)
                if checkbytes == b'':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for URL'}
                    return {'status': False, 'error': unpackingerror}
                if checkbytes == b'\x00':
                    break
                memberurl += checkbytes
            try:
                memberurl = memberurl.decode()
            except UnicodeDecodeError:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid URL'}
                return {'status': False, 'error': unpackingerror}

            # title
            membertitle = b''
            while True:
                checkbytes = checkfile.read(1)
                if checkbytes == b'':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for Title'}
                    return {'status': False, 'error': unpackingerror}
                if checkbytes == b'\x00':
                    break
                membertitle += checkbytes

            try:
                membertitle = membertitle.decode()
            except UnicodeDecodeError:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid Title'}
                return {'status': False, 'error': unpackingerror}

            if memberurl == '' and membertitle == '':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no URL and no Title'}
                return {'status': False, 'error': unpackingerror}

            # then try to extract the data from the blob,
            # but only for the relevant entries for now.
            if namespace not in contentnamespaces:
                continue

            # store the old offset
            oldoffset = checkfile.tell()

            # jump to the cluster and skip the first byte
            checkfile.seek(offset + clusterpointers[clusternumber] + 1)
            if clusterinfo[clusternumber]['compressed']:

                decompressor = lzma.LZMADecompressor()
                checkbytes = checkfile.read(1024)
                # then try to decompress the data.
                try:
                    unpackeddata = decompressor.decompress(checkbytes)
                except Exception as e:
                    # no data could be successfully unpacked
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not valid XZ data'}
                    return {'status': False, 'error': unpackingerror}
            else:
                bloboffsets = clusterinfo[clusternumber]['bloboffsets']
                if blobnumber >= len(bloboffsets) - 1:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'wrong blob number'}
                    return {'status': False, 'error': unpackingerror}

                # first create the output file
                if memberurl == '':
                    outfilename = membertitle
                else:
                    outfilename = memberurl

                if os.path.isabs(outfilename):
                    # TODO: this creates the absolute path and may pollute
                    # the filesystem?
                    os.makedirs(os.path.dirname(outfilename), exist_ok=True)
                    outfilename = os.path.relpath(outfilename.name, '/')

                blobsize = bloboffsets[blobnumber+1] - bloboffsets[blobnumber]

                checkfile.seek(bloboffsets[blobnumber], os.SEEK_CUR)

                unpackedname_rel = os.path.normpath(os.path.join(unpackdir, outfilename))
                unpackedname_full = scanenvironment.unpack_path(unpackedname_rel)
                unpackeddir_full = os.path.dirname(unpackedname_full)
                os.makedirs(unpackeddir_full, exist_ok=True)
                outfile = open(unpackedname_full, 'wb')
                os.sendfile(outfile.fileno(), checkfile.fileno(), checkfile.tell(), blobsize)
                outfile.close()
                unpackedfilesandlabels.append((unpackedname_rel, []))

            # and return to the old offset
            checkfile.seek(oldoffset)

    # finally read the checksum, which involves reading
    # *all* data up until the checksum
    # First read the checksum stored in the file.
    checkfile.seek(offset + checksumpos)
    checksum = checkfile.read(16)

    # then seek to the start of the archive
    checkfile.seek(offset)

    bytestoread = checksumpos
    readsize = min(10240, bytestoread)
    bytebuffer = bytearray(readsize)
    zimmd5 = hashlib.new('md5')

    while True:
        bytesread = checkfile.readinto(bytebuffer)
        if bytesread == 0:
            break
        bufferlen = min(readsize, bytestoread)
        checkbytes = memoryview(bytebuffer[:bufferlen])
        zimmd5.update(checkbytes)
        bytestoread -= bufferlen
        if bytestoread == 0:
            break

    checkfile.close()

    if checksum != zimmd5.digest():
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong checksum'}
        return {'status': False, 'error': unpackingerror}

    # file is a ZIM file, so record how much data was unpacked
    unpackedsize = checksumpos + 16

    if offset == 0 and unpackedsize == filesize:
        labels.append('zim')
        labels.append('archive')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_zim.signatures = {'zim': b'\x5a\x49\x4d\x04'}
unpack_zim.minimum_size = 80


# Label audio calibration database files from Qualcomm.
# This analysis was based on a few samples found inside the
# firmware of several Android devices using a Qualcomm chipset.
def unpack_acdb(fileresult, scanenvironment, offset, unpackdir):
    '''Verify Qualcomm's ACDB files'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # only support files starting at offset 0 for now
    if offset != 0:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'offset other than 0 not supported'}
        return {'status': False, 'error': unpackingerror}

    # header seems to be at least 32 bytes
    if filesize - offset < 32:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the offset.
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    # next 8 bytes are NULL bytes
    checkbytes = checkfile.read(8)
    if checkbytes != b'\x00\x00\x00\x00\x00\x00\x00\x00':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid header data'}
        return {'status': False, 'error': unpackingerror}

    # next 4 bytes can be various values, such as "AVDB"
    # "GCDB" or "CCDB"
    checkbytes = checkfile.read(4)
    if checkbytes not in [b'AVDB', b'GCDB', b'CCDB']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid header data'}
        return {'status': False, 'error': unpackingerror}

    # then four NULL bytes
    checkbytes = checkfile.read(4)
    if checkbytes != b'\x00\x00\x00\x00':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid header data'}
        return {'status': False, 'error': unpackingerror}

    # read four bytes to find the file size, minus 0x20 (32) bytes
    checkbytes = checkfile.read(4)
    recordedfilesize = int.from_bytes(checkbytes, byteorder='little')

    # and then apparently again (why? no idea)
    checkbytes = checkfile.read(4)
    recordedfilesize2 = int.from_bytes(checkbytes, byteorder='little')
    if recordedfilesize != recordedfilesize2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid header data'}
        return {'status': False, 'error': unpackingerror}

    # data cannot be outside of the file
    if recordedfilesize + 32 - offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for ACDB data'}
        return {'status': False, 'error': unpackingerror}

    # don't support carving right now
    if recordedfilesize + 32 - offset < filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'carving not supported'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = recordedfilesize + 32

    if offset == 0 and unpackedsize == filesize:
        labels.append('acdb')
        labels.append('resource')

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

unpack_acdb.signatures = {'acdb': b'QCMSNDDB'}


# https://sqlite.org/fileformat.html
def unpack_sqlite(fileresult, scanenvironment, offset, unpackdir):
    '''Label/verify/carve SQLite databases'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize - offset < 100:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the offset
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+16)
    unpackedsize += 16

    # page size "Must be a power of two between 512 and 32768 inclusive,
    # or the value 1 representing a page size of 65536."
    checkbytes = checkfile.read(2)
    pagesize = int.from_bytes(checkbytes, byteorder='big')
    if pagesize == 1:
        pagesize = 65536
    else:
        if pagesize < 512 or pagesize > 32768:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid page size'}
            return {'status': False, 'error': unpackingerror}
        if pow(2, int(math.log2(pagesize))) != pagesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid page size'}
            return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # file format write version, 1 or 2
    checkbytes = checkfile.read(1)
    if ord(checkbytes) not in [1, 2]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid format write version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # file format read version, 1 or 2
    checkbytes = checkfile.read(1)
    if ord(checkbytes) not in [1, 2]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid format read version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # bytes for unused reserved space, usually 0, skip for now
    checkbytes = checkfile.read(1)
    reservedspacebytes = ord(checkbytes)
    unpackedsize += 1

    # maximum embedded payload fraction. "Must be 64."
    checkbytes = checkfile.read(1)
    if ord(checkbytes) != 64:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid maximum embedded payload fraction'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # minimum embedded payload fraction. "Must be 32."
    checkbytes = checkfile.read(1)
    if ord(checkbytes) != 32:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid minimum embedded payload fraction'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # leaf payload fraction. "Must be 32."
    checkbytes = checkfile.read(1)
    if ord(checkbytes) != 32:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid leaf payload fraction'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # file change counter
    checkbytes = checkfile.read(4)
    filechangecounter = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # size of database in pages
    checkbytes = checkfile.read(4)
    dbsizeinpages = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    if offset + (dbsizeinpages * pagesize) > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for database'}
        return {'status': False, 'error': unpackingerror}

    # page number of the first freelist trunk page
    checkbytes = checkfile.read(4)
    firstfreelistpage = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # total number of freelist pages
    checkbytes = checkfile.read(4)
    freelistpages = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # schema cookie
    checkbytes = checkfile.read(4)
    schemacookie = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # schema format. "Supported schema formats are 1, 2, 3, and 4."
    checkbytes = checkfile.read(4)
    schemaformat = int.from_bytes(checkbytes, byteorder='big')
    if schemaformat not in [1, 2, 3, 4]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'unsupported schema format'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # default page cache size
    checkbytes = checkfile.read(4)
    defaultpagecachesize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # largest b-tree page
    checkbytes = checkfile.read(4)
    largestbtreepage = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # database text encoding
    checkbytes = checkfile.read(4)
    textencoding = int.from_bytes(checkbytes, byteorder='big')
    if textencoding not in [1, 2, 3]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'unsupported text encoding'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # user version
    checkbytes = checkfile.read(4)
    userversion = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # incremental vacuum mode
    checkbytes = checkfile.read(4)
    incrementalvacuummode = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # application id
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    # padding, "must be zero"
    checkbytes = checkfile.read(20)
    if checkbytes != b'\x00' * 20:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid padding bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 20

    # version valid for number
    checkbytes = checkfile.read(4)
    versionvalidfornumber = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # version of SQLite that last modified the file
    checkbytes = checkfile.read(4)
    sqliteversionnumber = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # The header of the file is valid. That doesn't mean that the file
    # itself is valid. On various Android systems there are SQLite files
    # that work, but where lots of fields in the header do not make sense
    # such as the number of pages. These are a bit more difficult to
    # detect.
    if dbsizeinpages == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'no pages in database (Android device?)'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = dbsizeinpages * pagesize
    sqlitetables = []

    # extra sanity checks: see if the database can be
    # opened with Python's built-in sqlite3 module.
    if offset == 0 and filesize == unpackedsize:
        checkfile.close()
        dbopen = False
        try:
            testconn = sqlite3.connect('file:%s?mode=ro' % filename_full, uri=True)
            testcursor = testconn.cursor()
            dbopen = True
            testcursor.execute('select name, tbl_name, sql from sqlite_master;')
            tablenames = testcursor.fetchall()
            testcursor.close()
            testconn.close()
            for t in tablenames:
                sqlitetable = {}
                sqlitetable['name'] = t[0]
                sqlitetable['tbl_name'] = t[1]
                sqlitetable['sql'] = t[2]
                sqlitetables.append(sqlitetable)
        except Exception as e:
            if dbopen:
                testcursor.close()
                testconn.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid SQLite database'}
            return {'status': False, 'error': unpackingerror}
        labels.append('sqlite3')
        labels.append('database')

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.sqlite3")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    # extra sanity checks: see if the database can be
    # opened with Python's built-in sqlite3 module.
    dbopen = False
    try:
        testconn = sqlite3.connect('file:%s?mode=ro' % outfile_full, uri=True)
        testcursor = testconn.cursor()
        dbopen = True
        testcursor.execute('select name, tbl_name, sql from sqlite_master;')
        tablenames = testcursor.fetchall()
        testcursor.close()
        testconn.close()
        for t in tablenames:
            sqlitetable = {}
            sqlitetable['name'] = t[0]
            sqlitetable['tbl_name'] = t[1]
            sqlitetable['sql'] = t[2]
            sqlitetables.append(sqlitetable)
    except Exception as e:
        if dbopen:
            testcursor.close()
            testconn.close()
        os.unlink(outfile_full)
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid SQLite database'}
        return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfile_rel, ['database', 'sqlite3', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_sqlite.signatures = {'sqlite3': b'SQLite format 3\x00'}
unpack_sqlite.minimum_size = 100


# Many firmware files for Broadcom devices start with a TRX header. While
# data can be perfectly unpacked without looking at the header (as the
# partitions are simply concatenated) this is looked at to be a bit more
# accurate.
#
# Specifications:
#
# https://openwrt.org/docs/techref/header
# http://web.archive.org/web/20190127154419/https://openwrt.org/docs/techref/header
def unpack_trx(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Broadcom TRX file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if offset + 28 > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset + 4)
    unpackedsize += 4

    # length of header plus data
    checkbytes = checkfile.read(4)
    trxlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + trxlength > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data outside of file'}
        return {'status': False, 'error': unpackingerror}

    if offset + trxlength < 28:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid length for header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # CRC32 value, ignore for now
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    # TRX flags, ignore for now
    checkbytes = checkfile.read(2)
    unpackedsize += 2

    # TRX version
    checkbytes = checkfile.read(2)
    trxversion = int.from_bytes(checkbytes, byteorder='little')
    if trxversion not in [1, 2]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid TRX version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # depending on the TRX version there are 3 or 4 partition offsets
    checkbytes = checkfile.read(4)
    offset1 = int.from_bytes(checkbytes, byteorder='little')
    if offset + offset1 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'partition 1 data outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    checkbytes = checkfile.read(4)
    offset2 = int.from_bytes(checkbytes, byteorder='little')
    if offset + offset2 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'partition 2 data outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    checkbytes = checkfile.read(4)
    offset3 = int.from_bytes(checkbytes, byteorder='little')
    if offset + offset3 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'partition 3 data outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    if trxversion == 2:
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for partition'}
            return {'status': False, 'error': unpackingerror}
        offset4 = int.from_bytes(checkbytes, byteorder='little')
        if offset + offset4 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'partition 4 data outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # write partition 1
    if offset1 != 0:
        if offset2 != 0:
            partitionsize = offset2 - offset1
        elif offset3 != 0:
            partitionsize = offset3 - offset1
        else:
            if trxversion == 2:
                partitionsize = offset4 - offset1
            else:
                partitionsize = trxlength - offset1
        if partitionsize > 0:
            outfile_rel = os.path.join(unpackdir, "partition1")
            outfile_full = scanenvironment.unpack_path(outfile_rel)
            outfile = open(outfile_full, 'wb')
            os.sendfile(outfile.fileno(), checkfile.fileno(), offset+offset1, partitionsize)
            outfile.close()
            unpackedfilesandlabels.append((outfile_rel, []))

    # write partition 2
    if offset2 != 0:
        if offset3 != 0:
            partitionsize = offset3 - offset2
        else:
            if trxversion == 2:
                partitionsize = offset4 - offset2
            else:
                partitionsize = trxlength - offset2
        if partitionsize > 0:
            outfile_rel = os.path.join(unpackdir, "partition2")
            outfile_full = scanenvironment.unpack_path(outfile_rel)
            outfile = open(outfile_full, 'wb')
            os.sendfile(outfile.fileno(), checkfile.fileno(), offset+offset2, partitionsize)
            outfile.close()
            unpackedfilesandlabels.append((outfile_rel, []))

    # write partition 3
    if offset3 != 0:
        if trxversion == 2 and offset4 != 0:
            partitionsize = offset4 - offset3
        else:
            partitionsize = trxlength - offset3
        if partitionsize > 0:
            outfile_rel = os.path.join(unpackdir, "partition3")
            outfile_full = scanenvironment.unpack_path(outfile_rel)
            outfile = open(outfile_full, 'wb')
            os.sendfile(outfile.fileno(), checkfile.fileno(), offset+offset3, partitionsize)
            outfile.close()
            unpackedfilesandlabels.append((outfile_rel, []))

    # write partition 4 if needed
    if trxversion == 2:
        if offset4 != 0:
            partitionsize = trxlength - offset4
            if partitionsize > 0:
                outfile_rel = os.path.join(unpackdir, "partition4")
                outfile_full = scanenvironment.unpack_path(outfile_rel)
                outfile = open(outfile_full, 'wb')
                os.sendfile(outfile.fileno(), checkfile.fileno(), offset+offset4, partitionsize)
                outfile.close()
                unpackedfilesandlabels.append((outfile_rel, []))

    checkfile.close()
    unpackedsize = trxlength
    if offset == 0 and filesize == unpackedsize:
        labels.append('trx')
        labels.append('firmware')
        labels.append('broadcom')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_trx.signatures = {'trx': b'HDR0'}
unpack_trx.minimum_size = 28


# /usr/share/magic
# https://en.wikipedia.org/wiki/Compress
# https://github.com/vapier/ncompress/releases
# https://wiki.wxwidgets.org/Development:_Z_File_Format
def unpack_compress(fileresult, scanenvironment, offset, unpackdir):
    '''Unpack UNIX compress'd data'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if shutil.which('uncompress') is None:
        if shutil.which('uncompress-ncompress') is None:
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'uncompress program not found'}
            return {'status': False, 'error': unpackingerror}
        uncompress = 'uncompress-ncompress'
    else:
        uncompress = 'uncompress'

    # open the file, skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+2)

    # the next byte contains the "bits per code" field
    # which has to be between 9 (inclusive) and 16 (inclusive)
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for'}
        return {'status': False, 'error': unpackingerror}

    bitspercode = ord(checkbytes) & 0x1f
    if bitspercode < 9 or bitspercode > 16:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid bits per code'}
        return {'status': False, 'error': unpackingerror}

    # like deflate compress can work on streams
    # As a test some data can be uncompressed.
    # First seek back to the original offset...
    checkfile.seek(offset)

    # ... read some data...
    testdata = checkfile.read(1024)

    # ...and run 'uncompress' to see if anything can be compressed at all
    p = subprocess.Popen([uncompress], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (standard_out, standard_error) = p.communicate(testdata)
    if len(standard_out) == 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid compress\'d data'}
        return {'status': False, 'error': unpackingerror}

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    havetmpfile = False
    if offset != 0:
        temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory, suffix='.Z')
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, filesize - offset)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True

    checkfile.close()

    if filename_full.suffix.lower() == '.z':
        outfile_rel = os.path.join(unpackdir, filename_full.stem)
    elif filename_full.suffix.lower() == '.tz':
        outfile_rel = os.path.join(unpackdir, filename_full.stem) + ".tar"
    else:
        outfile_rel = os.path.join(unpackdir, "unpacked-from-compress")

    outfile_full = scanenvironment.unpack_path(outfile_rel)
    outfile = open(outfile_full, 'wb')

    if havetmpfile:
        p = subprocess.Popen(['uncompress', '-c', temporaryfile[1]], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(['uncompress', '-c', filename_full], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

    (standard_out, standard_error) = p.communicate()
    if p.returncode != 0 and standard_error != b'':
        outfile.close()
        os.unlink(outfile_full)
        if havetmpfile:
            os.unlink(temporaryfile[1])
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid compress file'}
        return {'status': False, 'error': unpackingerror}

    outfile.close()

    # clean up
    if havetmpfile:
        os.unlink(temporaryfile[1])

    unpackedfilesandlabels.append((outfile_rel, []))
    unpackedsize = filesize - offset

    if offset == 0:
        labels.append('compress')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# /usr/share/magic
unpack_compress.signatures = {'compress': b'\x1f\x9d'}


# bFLT binaries
#
# https://web.archive.org/web/20120123212024/http://retired.beyondlogic.org/uClinux/bflt.htm
#
# and some additional details:
#
# http://web.archive.org/web/20180317070540/https://blog.tangrs.id.au/2012/04/07/bflt-format-implementation-notes/
def unpack_bflt(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/carve a bFLT file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # header is 64 bytes
    if offset + 64 > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file, skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize = 4

    # version, only support version 4 now (due to lack of test files)
    checkbytes = checkfile.read(4)
    version = int.from_bytes(checkbytes, byteorder='big')
    if version != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'only version 4 is supported'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # first jump to the flags
    checkfile.seek(28, os.SEEK_CUR)
    checkbytes = checkfile.read(4)
    flags = int.from_bytes(checkbytes, byteorder='big')

    gzip_compressed = False

    # check if the data is gzip compressed
    if flags & 0x4 == 0x4:
        gzip_compressed = True

    # then seek back
    checkfile.seek(-32, os.SEEK_CUR)

    # offset to the first executable entry
    checkbytes = checkfile.read(4)
    offset_entry = int.from_bytes(checkbytes, byteorder='big')
    if offset + offset_entry > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'offset outside of file'}
        return {'status': False, 'error': unpackingerror}
    if offset_entry < 64:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid offset'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # now the data segments. If the data was gzip compressed, then these
    # values will be incorrect, as they are the values for the uncompressed
    # data, and the header is left untouched.
    # For GOT some other tricks need to be used (TODO)

    # offset to the data segment
    checkbytes = checkfile.read(4)
    offset_data_start = int.from_bytes(checkbytes, byteorder='big')
    if offset_data_start < 64:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid data start offset'}
        return {'status': False, 'error': unpackingerror}
    if not gzip_compressed:
        if offset + offset_data_start > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid data start offset'}
            return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # offset to end of the data segment
    checkbytes = checkfile.read(4)
    offset_data_end = int.from_bytes(checkbytes, byteorder='big')
    if offset_data_end < 64 or offset_data_end < offset_data_start:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid data end offset'}
        return {'status': False, 'error': unpackingerror}
    if not gzip_compressed:
        if offset + offset_data_end > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid data end offset'}
            return {'status': False, 'error': unpackingerror}

    unpackedsize += 4

    # uClinux.org website says:
    # "While the comments for the flat file header would suggest there is a
    # bss segment somewhere in the flat file, this is not true."

    # offset to end of the bss segment
    checkbytes = checkfile.read(4)
    offset_bss_end = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # stack size, not important
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # reloc_start
    checkbytes = checkfile.read(4)
    offset_reloc_start = int.from_bytes(checkbytes, byteorder='big')
    if offset_reloc_start < 64:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid reloc start offset'}
        return {'status': False, 'error': unpackingerror}
    if not gzip_compressed:
        if offset + offset_reloc_start > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid reloc start offset'}
            return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # reloc_count, skip for now
    checkbytes = checkfile.read(4)
    reloc_count = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # skip flags, already processed
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # then the build date (possibly 0 in older files)
    checkbytes = checkfile.read(4)
    builddate = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # then 20 bytes of filler
    checkbytes = checkfile.read(20)
    if checkbytes != 20 * b'\x00':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid padding bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 20

    if gzip_compressed:
        # try to unpack the gzip compressed data. Some files seem to have
        # been compressed with the multi-part gzip flag and other flags set.
        unpackresult = unpack_gzip(fileresult, scanenvironment, offset + offset_entry, unpackdir)
        if not unpackresult['status']:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid gzip compressed bFLT'}
            return {'status': False, 'error': unpackingerror}

        # set the unpacked size to include the gzip compressed data
        unpackedsize += unpackresult['length']

        # determine the length of the uncompressed data,
        # needs to be cleaned up
        tmp_rel = unpackresult['filesandlabels'][0][0]
        tmp_full = scanenvironment.unpack_path(tmp_rel)
        gzip_size = tmp_full.stat().st_size

        # now perform all the checks that couldn't be done
        # because the data is gzip compressed
        if offset_data_start > gzip_size + 64:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid data start offset'}
            return {'status': False, 'error': unpackingerror}
        if offset_data_end > gzip_size + 64:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid data end offset'}
            return {'status': False, 'error': unpackingerror}
        if offset_reloc_start > gzip_size + 64:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid reloc start offset'}
            return {'status': False, 'error': unpackingerror}

        # cleanup
        tmp_full.unlink()
    else:
        if offset + offset_reloc_start + reloc_count*4 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'relocation data outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize = offset_reloc_start + reloc_count*4

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels = ['bflt', 'executable']
    else:
        # else carve the file
        outfile_rel = os.path.join(unpackdir, "unpacked-from-blft")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, ['blft', 'executable', 'unpacked']))
        checkfile.close()

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# https://web.archive.org/web/20120123212024/http://retired.beyondlogic.org/uClinux/bflt.htm
unpack_bflt.signatures = {'bflt': b'bFLT'}
unpack_bflt.minimum_size = 64


# https://en.wikipedia.org/wiki/Torrent_file
# http://www.bittorrent.org/beps/bep_0003.html
# https://en.wikipedia.org/wiki/Bencode
def unpack_bittorrent(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/carve a BitTorrent tracker file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # open the file, skip part of the 'magic'
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+1)
    unpackedsize = 1

    torrent_elements = {}

    # parse each element. Depending on the type it will
    # be followed by different kinds of data.
    while True:
        curelem = ''
        sizebytes = b''
        end_of_torrent = False
        while True:
            checkbytes = checkfile.read(1)
            if checkbytes == b'e':
                unpackedsize += 1
                end_of_torrent = True
                break
            if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not a valid torrent file'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 1
            if checkbytes == b':':
                break
            sizebytes += checkbytes

        if end_of_torrent:
            break
        try:
            elemsize = int(sizebytes)
        except ValueError:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid length for element'}
            return {'status': False, 'error': unpackingerror}

        if checkfile.tell() + elemsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for element'}
            return {'status': False, 'error': unpackingerror}

        elembytes = checkfile.read(elemsize)
        try:
            curelem = elembytes.decode()
        except UnicodeDecodeError:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid tracker URL'}
            return {'status': False, 'error': unpackingerror}

        unpackedsize += elemsize

        if curelem in ['announce', 'comment']:
            parseres = parse_bittorrent_bytestring(checkfile, checkfile.tell(), filesize)
            if not parseres['status']:
                checkfile.close()
                return parseres
            unpackedsize += parseres['size']
            torrent_elements[curelem] = parseres['value']
        elif curelem in ['creation date']:
            # integer value
            valuebytes = b''
            while True:
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not a valid torrent file'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 1
                if checkbytes == b'i':
                    continue
                if checkbytes == b'e':
                    break
                valuebytes += checkbytes
        elif curelem in ['httpseeds']:
            # BEP-0017
            checkbytes = checkfile.read(1)
            httpseeds = []
            if checkbytes != b'l':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid %s' % curelem}
                return {'status': False, 'error': unpackingerror}

            unpackedsize += 1
            while True:
                checkbytes = checkfile.read(1)
                if checkbytes == b'e':
                    unpackedsize += 1
                    break
                checkfile.seek(-1, os.SEEK_CUR)
                parseres = parse_bittorrent_bytestring(checkfile, checkfile.tell(), filesize)
                if not parseres['status']:
                    checkfile.close()
                    return parseres
                unpackedsize += parseres['size']
                httpseeds.append(parseres['value'])
            torrent_elements[curelem] = httpseeds
        elif curelem in ['info']:
            # dictionary
            torrent_info = {}
            checkbytes = checkfile.read(1)
            if checkbytes != b'd':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid %s' % curelem}
                return {'status': False, 'error': unpackingerror}

            unpackedsize += 1
            while True:
                checkbytes = checkfile.read(1)
                if checkbytes == b'e':
                    unpackedsize += 1
                    break
                checkfile.seek(-1, os.SEEK_CUR)
                parseres = parse_bittorrent_bytestring(checkfile, checkfile.tell(), filesize)
                if not parseres['status']:
                    checkfile.close()
                    return parseres
                unpackedsize += parseres['size']
                if parseres['value'] == 'name':
                    nameres = parse_bittorrent_bytestring(checkfile, checkfile.tell(), filesize)
                    if not nameres['status']:
                        checkfile.close()
                        return nameres
                    unpackedsize += nameres['size']
                    torrent_info['name'] = nameres['value']
                elif parseres['value'] in ['length', 'piece length']:
                    valuebytes = b''
                    while True:
                        checkbytes = checkfile.read(1)
                        if len(checkbytes) != 1:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'not a valid torrent file'}
                            return {'status': False, 'error': unpackingerror}
                        unpackedsize += 1
                        if checkbytes == b'i':
                            continue
                        if checkbytes == b'e':
                            break
                        valuebytes += checkbytes
                    try:
                        value = int(valuebytes)
                    except ValueError:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'invalid integer'}
                        return {'status': False, 'error': unpackingerror}
                    torrent_info[parseres['value']] = value
                if parseres['value'] == 'pieces':
                    pieceres = parse_bittorrent_bytestring(checkfile, checkfile.tell(), filesize, raw=True, skip=True)
                    if not pieceres['status']:
                        checkfile.close()
                        return pieceres
                    unpackedsize += pieceres['size']
            torrent_elements[curelem] = torrent_info

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels = ['resource', 'torrent']
    else:
        # else carve the file
        outfile_rel = os.path.join(unpackdir, "unpacked-from-torrent")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, ['resource', 'torrent', 'unpacked']))
        checkfile.close()

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels,
            'metadata': torrent_elements}

unpack_bittorrent.signatures = {'bittorrent': b'd8:announce'}


def parse_bittorrent_bytestring(checkfile, offset, filesize, raw=False, skip=False):
    '''Helper function to parse BitTorrent bytes strings'''
    checkfile.seek(offset)
    sizebytes = b''
    unpackedsize = 0

    while True:
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not a valid torrent file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
        if checkbytes == b':':
            break
        sizebytes += checkbytes

    try:
        elemsize = int(sizebytes)
    except ValueError:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid length for element'}
        return {'status': False, 'error': unpackingerror}

    try:
        value_size = int(sizebytes)
    except ValueError:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid length for %s' % curelem}
        return {'status': False, 'error': unpackingerror}

    if checkfile.tell() + value_size > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for elem %s' % curelem}
        return {'status': False, 'error': unpackingerror}

    if not skip:
        value_bytes = checkfile.read(value_size)
        if not raw:
            try:
                elem_value = value_bytes.decode()
            except UnicodeDecodeError:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid tracker URL'}
                return {'status': False, 'error': unpackingerror}
        else:
            elem_value = b''
    else:
        checkfile.seek(value_size, os.SEEK_CUR)
        elem_value = b''

    unpackedsize += value_size
    return {'status': True, 'size': unpackedsize, 'value': elem_value}


# https://github.com/pcapng/pcapng
# only process little endian files
def unpack_pcapng(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/carve a pcapng file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # standard blocks
    interface_block = 0x1
    simple_packet_block = 0x3
    name_resolution_block = 0x4
    interface_statistics_block = 0x5
    enhanced_packet_block = 0x6
    systemd_journal_export_block = 0x9
    decryption_secrets_block = 0xa
    custom_block = 0xbad
    custom_block2 = 0x40000bad
    regular_blocks = [interface_block, simple_packet_block,
                      name_resolution_block, interface_statistics_block,
                      enhanced_packet_block, systemd_journal_export_block,
                      decryption_secrets_block, custom_block,
                      custom_block2]

    # project/vendor specific blocks
    hone_blocks = [0x101, 0x102]
    sysdig_blocks = [0x201, 0x202, 0x203, 0x204, 0x205, 0x206, 0x207,
                     0x208, 0x209, 0x210, 0x211, 0x212, 0x213]

    all_blocks = regular_blocks + hone_blocks + sysdig_blocks

    # open the file
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)

    # process the blocks
    sectionheaderseen = False
    dataprocessed = False
    byteorder = 'little'
    while True:
        # block is at least 12 bytes
        if filesize - checkfile.tell() < 12:
            break
        # first the block type
        checkbytes = checkfile.read(4)
        if checkbytes == b'\x0a\x0d\x0d\x0a':
            sectionheaderseen = True
        else:
            if not sectionheaderseen:
                # section header block is mandatory
                break
            block_type = int.from_bytes(checkbytes, byteorder=byteorder)

            # only process blocks defined in the specification
            if not block_type in all_blocks:
                break

        # then the block size, which includes the block type
        # and the two "block total length" blocks
        checkbytes = checkfile.read(4)
        block_length = int.from_bytes(checkbytes, byteorder=byteorder)
        if block_length == 0:
            break
        if filesize - checkfile.tell() < block_length-12:
            break

        # skip the bytes
        checkfile.seek(block_length-12, os.SEEK_CUR)

        # read block length again
        checkbytes = checkfile.read(4)
        block_length2 = int.from_bytes(checkbytes, byteorder=byteorder)
        if block_length != block_length2:
            break
        unpackedsize += block_length
        dataprocessed = True

    if not dataprocessed:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no pcapng data processed'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels = ['pcapng']
    else:
        # else carve the file
        outfile_rel = os.path.join(unpackdir, "unpacked-from-pcapng")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, ['pcapng', 'unpacked']))
        checkfile.close()

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_pcapng.signatures = {'pcapng': b'\x0a\x0d\x0d\x0a'}


# https://wiki.wireshark.org/Development/LibpcapFileFormat
def unpack_pcap(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/carve a pcap file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    metadata = {}

    # header is 24 bytes
    if offset + 24 > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file, read the signature to determine byte order
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(4)

    nano_second = False
    if checkbytes == b'\xd4\xc3\xb2\xa1':
        byteorder = 'little'
    elif checkbytes == b'\x4d\x3c\xb2\xa1':
        byteorder = 'little'
        nano_second = True
    elif checkbytes == b'\xa1\xb2\xc3\xd4':
        byteorder = 'big'
    else:
        byteorder = 'big'
        nano_second = True
    unpackedsize += 4

    metadata['endian'] = byteorder
    metadata['nanoseconds'] = nano_second

    # major version
    checkbytes = checkfile.read(2)
    major = int.from_bytes(checkbytes, byteorder=byteorder)
    if major > 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # minor version
    checkbytes = checkfile.read(2)
    minor = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 2

    # this_zone
    checkbytes = checkfile.read(4)
    this_zone = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # sigfigs
    checkbytes = checkfile.read(4)
    sigfigs = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # snaplen
    checkbytes = checkfile.read(4)
    snaplen = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    # data link type
    checkbytes = checkfile.read(4)
    data_link_type = int.from_bytes(checkbytes, byteorder=byteorder)
    unpackedsize += 4

    data_unpacked = False
    packet_count = 1
    prev_ts_sec = 0

    # then the captured packets: packet header followed by packet data
    while True:
        # packet header is 16 bytes
        if checkfile.tell() + 16 > filesize:
            break

        # ts_sec
        checkbytes = checkfile.read(4)
        ts_sec = int.from_bytes(checkbytes, byteorder=byteorder)

        # extra sanity check, assuming that packets are in
        # chronological order. This is not always the case, for
        # example in the case of TCP Retransmissions.
        # More work needs to be done here. TODO.
        if ts_sec < prev_ts_sec:
            break
        prev_ts_sec = ts_sec

        # ts_usec, skip for now
        checkbytes = checkfile.read(4)
        ts_usec = int.from_bytes(checkbytes, byteorder=byteorder)

        # incl_len
        checkbytes = checkfile.read(4)
        incl_len = int.from_bytes(checkbytes, byteorder=byteorder)

        # orig_len
        checkbytes = checkfile.read(4)
        orig_len = int.from_bytes(checkbytes, byteorder=byteorder)

        if incl_len > orig_len:
            break

        if incl_len > snaplen:
            break

        if checkfile.tell() + incl_len > filesize:
            break

        unpackedsize += 16

        # skip the bytes
        checkfile.seek(incl_len, os.SEEK_CUR)
        unpackedsize += incl_len
        data_unpacked = True
        packet_count += 1

    metadata['count'] = packet_count

    if not data_unpacked:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no valid pcap data unpacked'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels = ['pcap']
    else:
        # else carve the file
        outfile_rel = os.path.join(unpackdir, "unpacked-from-pcap")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfile_rel, ['pcap', 'unpacked']))
        checkfile.close()

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels, 'metadata': metadata}

unpack_pcap.signatures = {'pcap_le': b'\xd4\xc3\xb2\xa1',
                          'pcap_be': b'\xa1\xb2\xc3\xd4',
                          'pcap_le_nano': b'\x4d\x3c\xb2\xa1',
                          'pcap_be_nano': b'\xa1\xb2\x3c\x4d'}
unpack_pcap.pretty = 'pcap'
unpack_pcap.minimum_size = 24


# Chrome extensions
#
# Specification:
#
# https://pypi.org/project/crx-unpack/
# https://chromium.googlesource.com/chromium/src.git/+/62.0.3178.1/chrome/common/extensions/docs/templates/articles/crx.html
def unpack_crx(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Chrome extension (CRX) file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if offset + 32 > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset + 4)
    unpackedsize += 4

    # version, has to be 2
    checkbytes = checkfile.read(4)
    version = int.from_bytes(checkbytes, byteorder='little')

    # public key length
    checkbytes = checkfile.read(4)
    public_key_length = int.from_bytes(checkbytes, byteorder='little')

    # signature length
    checkbytes = checkfile.read(4)
    signature_length = int.from_bytes(checkbytes, byteorder='little')

    if checkfile.tell() + public_key_length + signature_length > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for public key or signature'}
        return {'status': False, 'error': unpackingerror}

    # skip public key and signature
    checkfile.seek(public_key_length + signature_length, os.SEEK_CUR)
    zipoffset = checkfile.tell()
    unpackedsize = zipoffset - offset

    # read 4 bytes to see if it contains a valid ZIP header
    checkbytes = checkfile.read(4)
    if checkbytes != b'PK\x03\x04':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid ZIP data'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    crxres = unpack_zip(fileresult, scanenvironment, zipoffset, unpackdir)

    if not crxres['status']:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid ZIP data'}
        return {'status': False, 'error': unpackingerror}
    crxres['length'] += unpackedsize
    if offset == 0 and crxres['length'] == filesize:
        crxres['labels'].append('crx')
        crxres['labels'].append('chrome')
    return crxres


unpack_crx.signatures = {'crx': b'Cr24'}
unpack_crx.minimum_size = 32
