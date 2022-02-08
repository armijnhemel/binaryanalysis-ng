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
import re
import stat
import subprocess
import xml.dom
import hashlib
import pathlib
import brotli


# some external packages that are needed
import defusedxml.minidom
import pyaxmlparser

from FileResult import *
from UnpackParserException import UnpackParserException


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


'''Built in carvers/verifiers/unpackers for various Android formats (except
certain formats such as APK, which are with other unpackers).'''

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


# An unpacker for RIFF. This is a helper method used by unpackers for:
# * WAV
# * ANI
# https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
def unpack_riff(
        fileresult, scanenvironment, offset, unpackdir, validchunkfourcc,
        applicationname, applicationheader, brokenlength=False):
    '''Helper method to unpack RIFF based files'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    labels = []
    # First check if the file size is 12 bytes or more. If not, then
    # it is not a valid RIFF file.
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'less than 12 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    unpackedfilesandlabels = []
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    chunkstooffsets = {}

    # http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/riffmci.pdf
    # chapter 2
    infochunks = set([b'IARL', b'IART', b'ICMS', b'ICMT', b'ICOP', b'ICRD',
                      b'ICRP', b'IDIM', b'IDPI', b'IENG', b'IGNR', b'IKEY',
                      b'ILGT', b'IMED', b'INAM', b'IPLT', b'IPRD', b'ISBJ',
                      b'ISFT', b'ISHP', b'ISRC', b'ISRF', b'ITCH'])

    # Then open the file and read the first four bytes to see if
    # they are "RIFF".
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(4)
    if checkbytes != b'RIFF':
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no valid RIFF header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # Then read four bytes and check the length (stored
    # in little endian format)
    checkbytes = checkfile.read(4)
    rifflength = int.from_bytes(checkbytes, byteorder='little')
    # the data cannot go outside of the file. Some cases exist where
    # a broken length header is recorded (the length of the entire RIFF,
    # instead of "all following bytes").
    if not brokenlength:
        if rifflength + 8 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'wrong length', 'fatal': False}
            return {'status': False, 'error': unpackingerror}
    else:
        if rifflength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'wrong length', 'fatal': False}
            return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # Then read four bytes and check if they match the supplied header
    checkbytes = checkfile.read(4)
    if checkbytes != applicationheader:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'no valid %s header' % applicationname,
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # https://resources.oreilly.com/examples/9781565920583/blob/beb34c319e422d01ee485c5d423aad3bc8a69ce0/CDROM/GFF/VENDSPEC/MICRIFF/MS_RIFF.TXT
    validriffchunks = [b'LIST', b'DISP', b'JUNK', b'PAD']

    # then read chunks
    while True:
        if brokenlength:
            if checkfile.tell() == offset + rifflength:
                break
        else:
            if checkfile.tell() == offset + rifflength + 8:
                break
        haspadding = False
        chunkoffset = checkfile.tell() - offset
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset + unpackedsize,
                              'reason': 'no valid chunk header',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        if checkbytes not in validchunkfourcc and checkbytes not in validriffchunks:
            checkfile.close()
            unpackingerror = {'offset': offset + unpackedsize,
                              'reason': 'no valid chunk FourCC %s' % checkbytes,
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        if checkbytes not in chunkstooffsets:
            chunkstooffsets[checkbytes] = []
        chunkname = checkbytes
        chunkstooffsets[chunkname].append(chunkoffset)
        unpackedsize += 4

        # then the chunk size
        checkbytes = checkfile.read(4)
        chunklength = int.from_bytes(checkbytes, byteorder='little')
        if chunklength % 2 != 0:
            chunklength += 1
            haspadding = True
        curpos = checkfile.tell()
        if chunklength > filesize - curpos:
            checkfile.close()
            unpackingerror = {'offset': offset + unpackedsize,
                              'reason': 'wrong chunk length',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        # extra sanity for LIST chunks
        if chunkname == b'LIST':
            if chunklength < 4 and chunklength != 0:
                checkfile.close()
                unpackingerror = {'offset': offset + unpackedsize,
                                  'reason': 'wrong chunk length',
                                  'fatal': False}
                return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # finally skip over the bytes in the file
        if haspadding:
            checkfile.seek(curpos + chunklength-1)
            paddingbyte = checkfile.read(1)
            if not paddingbyte == b'\x00':
                checkfile.close()
                unpackingerror = {'offset': offset + unpackedsize,
                                  'reason': 'wrong value for padding byte length',
                                  'fatal': False}
                return {'status': False, 'error': unpackingerror}
        else:
            checkfile.seek(curpos + chunklength)
        unpackedsize += chunklength

    # extra sanity check to see if the size of the unpacked data
    # matches the declared size from the header.
    if not brokenlength:
        if unpackedsize != rifflength + 8:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unpacked size does not match declared size'}
            return {'status': False, 'error': unpackingerror}
    else:
        if unpackedsize != rifflength:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unpacked size does not match declared size'}
            return {'status': False, 'error': unpackingerror}

    # if the entire file is the RIFF file, then label it as such
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('riff')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels,
                'offsets': chunkstooffsets}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.%s" % applicationname.lower())
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    # TODO: missing labels?
    unpackedfilesandlabels.append(outfile_rel)

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels,
            'offsets': chunkstooffsets}


# test files for ANI: http://www.anicursor.com/diercur.html
# http://fileformats.archiveteam.org/wiki/Windows_Animated_Cursor#Sample_files
def unpack_ani(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve an ANI file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []

    # a list of valid ANI chunk FourCC
    validchunkfourcc = set([b'ICON', b'anih', b'rate', b'seq '])

    # Some ANI files have a broken RIFF header, so try to
    # detect if that is the case. This is not 100% foolproof.
    brokenlength = False

    # Then read four bytes and check the length (stored
    # in little endian format)
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    checkbytes = checkfile.read(4)
    rifflength = int.from_bytes(checkbytes, byteorder='little')
    if rifflength == filesize:
        brokenlength = True
    checkfile.close()

    unpackres = unpack_riff(fileresult, scanenvironment, offset, unpackdir, validchunkfourcc, 'ANI', b'ACON', brokenlength)
    if unpackres['status']:
        labels = unpackres['labels']
        if offset == 0 and unpackres['length'] == filesize:
            labels += ['ani', 'graphics']
        for result in unpackres['filesandlabels']:
            unpackedfilesandlabels.append((result, ['ani', 'graphics', 'unpacked']))
        return {'status': True, 'length': unpackres['length'],
                'filesandlabels': unpackedfilesandlabels, 'labels': labels}
    return {'status': False, 'error': unpackres['error']}

unpack_ani.signatures = {'ani': b'ACON'}
unpack_ani.offset = 8
unpack_ani.minimum_size = 12


# MNG specifications can be found at:
#
# http://www.libpng.org/pub/mng/spec/
# https://en.wikipedia.org/wiki/Multiple-image_Network_Graphics
#
# This format is almost never used and support for it in
# programs is spotty.
def unpack_mng(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a MNG file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize - offset < 52:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 52 bytes'}
        return {'status': False, 'error': unpackingerror}

    # open the file skip over the magic header bytes
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+8)
    unpackedsize = 8

    # Then process the MNG data. All data is in network byte order
    # (section 1). First read the size of the first chunk, which is
    # always 28 bytes (section 4.1.1).
    # Including the header, chunk type and CRC 40 bytes have to be read
    checkbytes = checkfile.read(40)
    if checkbytes[0:4] != b'\x00\x00\x00\x1c':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'no valid chunk length'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}

    # The first chunk *has* to be MHDR
    if checkbytes[4:8] != b'MHDR':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'no MHDR header'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}

    # then compute the CRC32 of bytes 4 - 24 (header + data)
    # and compare it to the CRC in the MNG file
    crccomputed = binascii.crc32(checkbytes[4:-4])
    crcstored = int.from_bytes(checkbytes[-4:], byteorder='big')
    if crccomputed != crcstored:
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'Wrong CRC'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 40

    # Then move on to the next chunks in similar fashion
    endoffilereached = False
    chunknames = set()

    while True:
        # read the chunk size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                              'reason': 'Could not read chunk size'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}
        chunksize = int.from_bytes(checkbytes, byteorder='big')
        if offset + chunksize > filesize:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                              'reason': 'MNG data bigger than file'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # read the chunk type, plus the chunk data
        checkbytes = checkfile.read(4+chunksize)
        chunktype = checkbytes[0:4]
        if len(checkbytes) != 4+chunksize:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                              'reason': 'Could not read chunk type'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}

        unpackedsize += 4+chunksize

        # compute the CRC
        crccomputed = binascii.crc32(checkbytes)
        checkbytes = checkfile.read(4)
        crcstored = int.from_bytes(checkbytes, byteorder='big')
        if crccomputed != crcstored:
            unpackingerror = {'offset': offset + unpackedsize,
                              'fatal': False, 'reason': 'Wrong CRC'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}

        # add the name of the chunk to the list of chunk names
        chunknames.add(chunktype)
        if chunktype == b'MEND':
            # MEND indicates the end of the file
            endoffilereached = True
            unpackedsize += 4
            break
        unpackedsize += 4

    # There has to be exactly 1 MEND chunk
    if endoffilereached:
        if offset == 0 and unpackedsize == filesize:
            checkfile.close()
            labels += ['mng', 'graphics']
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        # else carve the file. It is anonymous, so just give it a name
        outfile_rel = os.path.join(unpackdir, "unpacked.mng")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()

        unpackedfilesandlabels.append((outfile_rel, ['mng', 'graphics', 'unpacked']))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # There is no end of file, so it is not a valid MNG.
    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'No MEND found'}
    return {'status': False, 'error': unpackingerror}

unpack_mng.signatures = {'mng': b'\x8aMNG\x0d\x0a\x1a\x0a'}
unpack_mng.minimum_size = 52


# The specifications for PDF 1.7 are an ISO standard and can be found
# on the Adobe website:
#
# https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf
#
# with additional information at:
#
# https://www.adobe.com/devnet/pdf/pdf_reference.html
#
# The file structure is described in section 7.5.
#
# Test files for PDF 2.0 can be found at:
#
# https://github.com/pdf-association/pdf20examples
def unpack_pdf(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/carve a PDF file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    pdfinfo = {}

    # open the file and skip the offset
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+5)
    unpackedsize += 5

    # read the major version number and '.'
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for version number'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes not in [b'1.', b'2.']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid version number'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # read the minor version number
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for version number'}
        return {'status': False, 'error': unpackingerror}

    # section 7.5.2
    try:
        versionnumber = int(checkbytes)
    except ValueError:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid version number'}
        return {'status': False, 'error': unpackingerror}

    if versionnumber > 7:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid version number'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # then either LF, CR, or CRLF (section 7.5.1)
    # exception: ImageMagick 6.5.8-10 2010-12-17 Q16 (and possibly others)
    # sometimes included an extra space directly after the PDF version.
    checkbytes = checkfile.read(1)
    if checkbytes == b'\x20':
        unpackedsize += 1
        checkbytes = checkfile.read(1)
    if checkbytes not in [b'\x0a', b'\x0d']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong line ending'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # check if the line ending is CRLF
    if checkbytes == b'\x0d':
        checkbytes = checkfile.read(1)
        if checkbytes == b'\x0a':
            unpackedsize += 1
        else:
            checkfile.seek(-1, os.SEEK_CUR)

    validpdf = False
    validpdfsize = -1

    # keep a list of referencs for the entire document
    documentobjectreferences = {}

    # The difficulty with PDF is that the body has no fixed structure
    # but is referenced from a trailer at the end of the PDF, possibly
    # followed by incremental updates (section 7.5.6). As files might
    # have been concatenated simply jumping to the end of the file is
    # not an option (although it would work for most files). Therefore
    # the file needs to be read until the start of the trailer is found.
    # As an extra complication sometimes the updates are not appended
    # to the file, but prepended using forward references instead of
    # back references and then other parts of the PDF file having back
    # references, making the PDF file more of a random access file.
    while True:
        # continuously look for trailers until there is no
        # valid trailer anymore.
        startxrefpos = -1
        crossoffset = -1

        # keep track of the object references in a single
        # part of the document (either the original document
        # or an update to the document)
        objectreferences = {}

        # first seek to where data had already been read
        checkfile.seek(offset + unpackedsize)
        isvalidtrailer = True

        # Sometimes the value for the reference table in startxref is 0.
        # This typically only happens for some updates, and there should
        # be a Prev entry in the trailer dictionary.
        needsprev = False

        while True:
            # create a new buffer for every read, as buffers are
            # not flushed and old data might linger.
            pdfbuffer = bytearray(10240)
            bytesread = checkfile.readinto(pdfbuffer)
            if bytesread == 0:
                break

            pdfpos = pdfbuffer.find(b'startxref')
            if pdfpos != -1:
                startxrefpos = unpackedsize + pdfpos
                # extra sanity checks to check if it is really EOF
                # (defined in section 7.5.5):
                # * whitespace
                # * valid byte offset to last cross reference
                # * EOF marker

                # skip over 'startxref'
                checkfile.seek(offset + startxrefpos + 9)

                # then either LF, CR, or CRLF (section 7.5.1)
                checkbytes = checkfile.read(1)
                if checkbytes not in [b'\x0a', b'\x0d']:
                    startxrefpos = -1
                if checkbytes == b'\x0d':
                    checkbytes = checkfile.read(1)
                    if checkbytes != b'\x0a':
                        checkfile.seek(-1, os.SEEK_CUR)
                crossbuf = b''
                seeneol = False

                while True:
                    checkbytes = checkfile.read(1)
                    if checkbytes in [b'\x0a', b'\x0d']:
                        seeneol = True
                        break
                    if checkfile.tell() == filesize:
                        break
                    crossbuf += checkbytes
                if not seeneol:
                    isvalidtrailer = False
                    break

                # the value should be an integer followed by
                # LF, CR or CRLF.
                if crossbuf != b'':
                    try:
                        crossoffset = int(crossbuf)
                    except ValueError:
                        break
                if crossoffset != 0:
                    # the offset for the cross reference cannot
                    # be outside of the file.
                    if offset + crossoffset > checkfile.tell():
                        isvalidtrailer = False
                        break
                else:
                    needsprev = True
                if checkbytes == b'\x0d':
                    checkbytes = checkfile.read(1)
                if checkbytes != b'\x0a':
                    checkfile.seek(-1, os.SEEK_CUR)

                # now finally check EOF
                checkbytes = checkfile.read(5)
                seeneof = False
                if checkbytes != b'%%EOF':
                    isvalidtrailer = False
                    break

                seeneof = True

                # Most likely there are EOL markers, although the PDF
                # specification is not 100% clear about this:
                # section 7.5.1 indicates that EOL markers are part of
                # line by convention.
                # Section 7.2.3 says that comments should *not*
                # include "end of line" (but these two do not contradict)
                # which likely confused people.
                checkbytes = checkfile.read(1)
                if checkbytes in [b'\x0a', b'\x0d']:
                    if checkbytes == b'\x0d':
                        if checkfile.tell() != filesize:
                            checkbytes = checkfile.read(1)
                            if checkbytes != b'\x0a':
                                checkfile.seek(-1, os.SEEK_CUR)

                if checkfile.tell() == filesize:
                    break
                if seeneof:
                    break

            # check if the end of file was reached, without having
            # read a valid trailer.
            if checkfile.tell() == filesize:
                isvalidtrailer = False
                break

            # continue searching, with some overlap
            checkfile.seek(-10, os.SEEK_CUR)
            unpackedsize = checkfile.tell() - offset

        if not isvalidtrailer:
            break
        if startxrefpos == -1 or crossoffset == -1 or not seeneof:
            break

        unpackedsize = checkfile.tell() - offset

        # extra sanity check: look at the contents of the trailer dictionary
        checkfile.seek(startxrefpos-5)
        checkbytes = checkfile.read(5)
        if b'>>' not in checkbytes:
            # possibly a cross reference stream (section 7.5.8),
            # a comment line (iText seems to do this a lot)
            # or whitespace
            # TODO
            break

        endoftrailerpos = checkbytes.find(b'>>') + startxrefpos - 4

        trailerpos = -1

        # search the data backwards for the word "trailer"
        checkfile.seek(-50, os.SEEK_CUR)
        isstart = False
        while True:
            curpos = checkfile.tell()
            if curpos <= offset:
                isstart = True
            checkbytes = checkfile.read(50)
            trailerpos = checkbytes.find(b'trailer')
            if trailerpos != -1:
                trailerpos = curpos + trailerpos
                break
            if isstart:
                break
            checkfile.seek(-60, os.SEEK_CUR)

        # read the xref entries (section 7.5.4) as those
        # might be referenced in the trailer.
        checkfile.seek(offset+crossoffset+4)
        validxref = True
        if trailerpos - crossoffset > 0:
            checkbytes = checkfile.read(trailerpos - crossoffset - 4).strip()
            if b'\r\n' in checkbytes:
                objectdefs = checkbytes.split(b'\r\n')
            elif b'\r' in checkbytes:
                objectdefs = checkbytes.split(b'\r')
            else:
                objectdefs = checkbytes.split(b'\n')
            firstlineseen = False
            xrefseen = 0
            xrefcount = 0
            # the cross reference section might have
            # subsections. The first line is always
            # two integers
            for obj in objectdefs:
                if not firstlineseen:
                    # first line has to be two integers
                    linesplits = obj.split()
                    if len(linesplits) != 2:
                        validxref = False
                        break
                    try:
                        startxref = int(linesplits[0])
                        xrefcount = int(linesplits[1])
                        xrefcounter = int(linesplits[0])
                    except ValueError:
                        validxref = False
                        break
                    firstlineseen = True
                    xrefseen = 0
                    continue
                linesplits = obj.split()
                if len(linesplits) != 2 and len(linesplits) != 3:
                    validxref = False
                    break
                if len(linesplits) == 2:
                    # start of a new subsection, so first
                    # check if the previous subsection was
                    # actually valid.
                    if xrefcount != xrefseen:
                        validxref = False
                        break
                    linesplits = obj.split()
                    if len(linesplits) != 2:
                        validxref = False
                        break
                    try:
                        startxref = int(linesplits[0])
                        xrefcount = int(linesplits[1])
                        xrefcounter = int(linesplits[0])
                    except ValueError:
                        validxref = False
                        break
                    xrefseen = 0
                    continue
                elif len(linesplits) == 3:
                    # each of the lines consists of:
                    # * offset
                    # * generation number
                    # * keyword to indicate in use/free
                    if len(linesplits[0]) != 10:
                        validxref = False
                        break
                    if len(linesplits[1]) != 5:
                        validxref = False
                        break
                    if len(linesplits[2]) != 1:
                        validxref = False
                        break
                    try:
                        objectoffset = int(linesplits[0])
                    except ValueError:
                        validxref = False
                        break
                    try:
                        generation = int(linesplits[1])
                    except ValueError:
                        validxref = False
                        break
                    if linesplits[2] == b'n':
                        objectreferences[xrefcounter] = {}
                        objectreferences[xrefcounter]['offset'] = objectoffset
                        objectreferences[xrefcounter]['generation'] = generation
                        objectreferences[xrefcounter]['keyword'] = 'new'
                    elif linesplits[2] == b'f':
                        objectreferences[xrefcounter] = {}
                        objectreferences[xrefcounter]['offset'] = objectoffset
                        objectreferences[xrefcounter]['generation'] = generation
                        objectreferences[xrefcounter]['keyword'] = 'free'
                    else:
                        validxref = False
                        break
                    xrefcounter += 1
                    xrefseen += 1

            if xrefcount != xrefseen:
                validxref = False

            if not validxref:
                break

        # jump to the position where the trailer starts
        checkfile.seek(trailerpos)

        # and read the trailer, minus '>>'
        checkbytes = checkfile.read(endoftrailerpos - trailerpos)

        # extra sanity check: see if '<<' is present
        if b'<<' not in checkbytes:
            break

        # then split the entries
        trailersplit = checkbytes.split(b'\x0d\x0a')
        if len(trailersplit) == 1:
            trailersplit = checkbytes.split(b'\x0d')
            if len(trailersplit) == 1:
                trailersplit = checkbytes.split(b'\x0a')

        seenroot = False
        correctreference = True
        seenprev = False
        for i in trailersplit:
            if b'/' not in i:
                continue
            if b'/Root' in i:
                seenroot = True
            if b'/Info' in i:
                # indirect reference, section 7.3.10
                # Don't treat errors as fatal right now.
                infores = re.search(b'/Info\s+(\d+)\s+(\d+)\s+R', i)
                if infores is None:
                    continue
                (objectref, generation) = infores.groups()
                objectref = int(objectref)
                generation = int(generation)
                if objectref in objectreferences:
                    # seek to the position of the object in the
                    # file and read the data
                    checkfile.seek(offset + objectreferences[objectref]['offset'])

                    # first read a few bytes to check if it is
                    # actually the right object
                    checkbytes = checkfile.read(len(str(objectref)))
                    try:
                        cb = int(checkbytes)
                    except ValueError:
                        continue
                    if cb != objectref:
                        continue

                    # read a space
                    checkbytes = checkfile.read(1)
                    if checkbytes != b' ':
                        continue

                    # read the generation
                    checkbytes = checkfile.read(len(str(generation)))
                    try:
                        gen = int(checkbytes)
                    except ValueError:
                        continue
                    if gen != generation:
                        continue

                    # read a space
                    checkbytes = checkfile.read(1)
                    if checkbytes != b' ':
                        continue

                    # then read 'obj'
                    checkbytes = checkfile.read(3)
                    if checkbytes != b'obj':
                        continue

                    # now read until 'endobj' is reached
                    infobytes = b''
                    validinfobytes = True
                    while True:
                        checkbytes = checkfile.read(20)
                        infobytes += checkbytes
                        if infobytes == b'':
                            validinfobytes = False
                            break
                        if b'endobj' in infobytes:
                            break
                    if not validinfobytes:
                        continue
                    infobytes = infobytes.split(b'endobj', 1)[0].strip()
                    if b'<<' not in infobytes:
                        continue
                    if b'>>' not in infobytes:
                        continue
                    if infobytes[0] == b'<<' and infobytes[-1] == b'>>':
                        infobytes = infobytes[1:-1]
                    else:
                        infobytes = infobytes.split(b'>>', 1)[0]
                        infobytes = infobytes.split(b'<<', 1)[1]
                    # process according to section 14.3.3
                    # TODO
            if b'/Prev' in i:
                prevres = re.search(b'/Prev\s(\d+)', i)
                if prevres is not None:
                    prevxref = int(prevres.groups()[0])
                    seenprev = True
                    if offset + prevxref > filesize:
                        correctreference = False
                        break
                    checkfile.seek(offset + prevxref)
                    checkbytes = checkfile.read(4)
                    if checkbytes != b'xref':
                        correctreference = False
                        break
                    pdfinfo['updates'] = True

        # /Root element is mandatory
        if not seenroot:
            break

        if needsprev and not seenprev:
            break

        # references should be correct
        if not correctreference:
            break

        # so far the PDF file is valid (possibly including updates)
        # so record it as such and record until where the PDF is
        # considered valid.
        validpdf = True
        validpdfsize = unpackedsize

    if validpdf:
        if offset == 0 and validpdfsize == filesize:
            checkfile.close()
            labels.append('pdf')
            return {'status': True, 'length': validpdfsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        # else carve the file
        outfile_rel = os.path.join(unpackdir, "unpacked.pdf")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, validpdfsize)
        outfile.close()
        checkfile.close()

        unpackedfilesandlabels.append((outfile_rel, ['pdf', 'unpacked']))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    checkfile.close()
    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'not a valid PDF'}
    return {'status': False, 'error': unpackingerror}

unpack_pdf.signatures = {'pdf': b'%PDF-'}
