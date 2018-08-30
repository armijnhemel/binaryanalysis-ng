#!/usr/bin/python3

## Binary Analysis Next Generation (BANG!)
##
## This file is part of BANG.
##
## BANG is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License, version 3,
## as published by the Free Software Foundation.
##
## BANG is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License for more details.
##
## You should have received a copy of the GNU Affero General Public
## License, version 3, along with BANG.  If not, see
## <http://www.gnu.org/licenses/>
##
## Copyright 2018 - Armijn Hemel
## Licensed under the terms of the GNU Affero General Public License
## version 3
## SPDX-License-Identifier: AGPL-3.0-only

## Built in carvers/verifiers/unpackers for various formats.
##
## Native Python unpackers/carvers for:
##
##  1. WebP
##  2. WAV
##  3. ANI
##  4. gzip
##  5. LZMA
##  6. XZ
##  7. timezone files
##  8. tar
##  9. Apple Double encoded files
## 10. ICC (colour profile)
## 11. ZIP (store, deflate, bzip2, but lzma needs some more testing)
## 12. bzip2
## 13. XAR
## 14. ISO9660 (including RockRidge and zisofs)
## 15. lzip
## 16. WOFF (Web Open Font Format)
## 17. TrueType fonts
## 18. OpenType fonts
## 19. Vim swap files (whole file only)
## 20. Android sparse data image
## 21. Android backup files
## 22. ICO (MS Windows icons)
## 23. Chrome PAK (version 4 & 5, only if offset starts at 0)
## 24. GNU message catalog
## 25. RPM (missing: delta RPM)
## 26. AIFF/AIFF-C
## 27. terminfo (little endian, including ncurses extension, does not
##     recognize some wide character versions)
## 28. AU (Sun/NeXT audio)
## 29. JFFS2 (uncompressed, zlib, LZMA from OpenWrt)
## 30. CPIO (various flavours, little endian)
## 31. Sun Raster files (standard type only)
## 32. Intel Hex (text files only)
## 33. Motorola SREC (text files only)
## 34. MNG
## 35. Android sparse image files
## 36. Java class file
## 37. Android Dex/Odex (not OAT, just carving)
## 38. ELF (whole files only, basic)
## 39. SWF
##
## Unpackers/carvers needing external Python libraries or other tools
##
##  1. PNG/APNG (needs PIL)
##  2. ar/deb (needs binutils)
##  3. squashfs (needs squashfs-tools)
##  4. BMP (needs PIL)
##  5. GIF (needs PIL)
##  6. JPEG (needs PIL)
##  7. Microsoft Cabinet archives (requires cabextract)
##  8. RZIP (requires rzip)
##  9. 7z (requires external tools), single frame(?)
## 10. Windows Compiled HTML Help (requires external tools, version 3
##     only)
## 11. Windows Imaging file format (requires external tools, single
##     image only)
## 12. ext2/3/4 (missing: symbolic link support)
## 13. zstd (needs zstd package)
## 14. SGI image files (needs PIL)
## 15. Apple Icon Image (needs PIL)
## 16. LZ4 (requires LZ4 Python bindings)
## 17. VMware VMDK (requires qemu-img, whole file only)
## 18. QEMU qcow2 (requires qemu-img, whole file only)
## 19. VirtualBox VDI (requires qemu-img, whole file only,
##     Oracle flavour only)
## 20. XML
## 21. Snappy (needs python-snappy)
##
## For these unpackers it has been attempted to reduce disk I/O as much
## as possible using the os.sendfile() method, as well as techniques
## described in this blog post:
##
## https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import sys
import os
import shutil
import binascii
import string
import copy
import tempfile
import struct
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
import xml.dom.minidom
import hashlib
import re
import pathlib

## some external packages that are needed
import PIL.Image
import lz4
import lz4.frame
import snappy

encodingstotranslate = [ 'utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004'
                       , 'jisx0213', 'iso2022_jp', 'iso2022_jp_1'
                       , 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3'
                       , 'iso2022_jp_ext', 'iso2022_kr','shift_jis'
                       ,'shift_jis_2004', 'shift_jisx0213']

## Each unpacker has a specific interface:
##
## def unpacker(filename, offset, unpackdir)
##
## * filename: full file name (pathlib.PosixPath object)
## * offset: offset inside the file where the file system, compressed
##   file media file possibly starts
## * unpackdir: the target directory where data should be written to
##
## The unpackers are supposed to return a dictionary with the following
## field:
##
## * unpack status (boolean) to indicate whether or not any data was
##   unpacked
##
## Depending on the value of the status several other fields are
## expected. For successful scans (unpack status == True) the following
## should be present:
##
## * unpack size to indicate what part of the data was unpacked
## * a list of tuples (file, labels) that were unpacked from the file.
##   The labels could be used to indicate that a file has a certain
##   status and that it should not be unpacked as it is already known
##   what the file is (example: PNG)
## * a list of labels for the file
## * a dict with extra information (structure depending on type
##   of scan)
##
## If the scan was unsuccessful (unpack status == False), the following
## should be present:
##
## * a dict with a possible error.
##
## The error dict has the following items:
##
## * fatal: boolean to indicate whether or not the error is a fatal
##   error (such as disk full, etc.) so BANG should be stopped.
##   Non-fatal errors are format violations (files, etc.)
## * offset: offset where the error occured
## * reason: human readable description of the error

## A verifier for the WebP file format.
## Uses the description of the WebP file format as described here:
##
## https://developers.google.com/speed/webp/docs/riff_container
##
## A blog post describing how this method was implemented can be
## found here:
##
## http://binary-analysis.blogspot.com/2018/06/walkthrough-webp-file-format.html
def unpackWebP(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []

    ## a list of valid WebP chunk FourCC
    ## also contains the deprecated FRGM
    validchunkfourcc = set([b'ALPH', b'ANIM', b'ANMF', b'EXIF', b'FRGM',
                           b'ICCP', b'VP8 ', b'VP8L', b'VP8X', b'XMP '])
    unpackres = unpackRIFF(filename, offset, unpackdir, validchunkfourcc, 'WebP', b'WEBP', filesize)
    if unpackres['status']:
        labels = copy.deepcopy(unpackres['labels'])
        if offset == 0 and unpackres['length'] == filesize:
            labels += ['webp', 'graphics']
        for u in unpackres['filesandlabels']:
            unpackedfilesandlabels.append((u, ['webp', 'graphics', 'unpacked']))
        return {'status': True, 'length': unpackres['length'],
                'filesandlabels': unpackedfilesandlabels, 'labels': labels}
    return {'status': False, 'error': unpackres['error']}

## A verifier for the WAV file format.
## Uses the description of the WAV file format as described here:
##
## https://sites.google.com/site/musicgapi/technical-documents/wav-file-format
## http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
def unpackWAV(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []

    ## a list of valid WAV chunk FourCC
    validchunkfourcc = set([b'LGWV', b'bext', b'cue ', b'data', b'fact',
                            b'fmt ', b'inst', b'labl', b'list', b'ltxt',
                            b'note', b'plst', b'smpl'])
    unpackres = unpackRIFF(filename, offset, unpackdir, validchunkfourcc, 'WAV', b'WAVE', filesize)
    if unpackres['status']:
        labels = copy.deepcopy(unpackres['labels'])
        if offset == 0 and unpackres['length'] == filesize:
            labels += ['wav', 'audio']
        for u in unpackres['filesandlabels']:
            unpackedfilesandlabels.append((u, ['wav', 'audio', 'unpacked']))
        return {'status': True, 'length': unpackres['length'],
                'filesandlabels': unpackedfilesandlabels, 'labels': labels}
    return {'status': False, 'error': unpackres['error']}

## An unpacker for RIFF. This is a helper method used by unpackers for:
## * WebP
## * WAV
## * ANI
## https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
def unpackRIFF(filename, offset, unpackdir, validchunkfourcc, applicationname, applicationheader, filesize, brokenlength=False):
    labels = []
    ## First check if the file size is 12 bytes or more. If not, then
    ## it is not a valid RIFF file.
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'less than 12 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    unpackedfilesandlabels = []

    ## Then open the file and read the first four bytes to see if
    ## they are "RIFF".
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(4)
    if checkbytes != b'RIFF':
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no valid RIFF header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## Then read four bytes and check the length (stored
    ## in little endian format)
    checkbytes = checkfile.read(4)
    rifflength = int.from_bytes(checkbytes, byteorder='little')
    ## the data cannot go outside of the file. Some cases exist where
    ## a broken length header is recorded (the length of the entire RIFF,
    ## instead of "all following bytes").
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

    ## Then read four bytes and check if they match the supplied header
    checkbytes = checkfile.read(4)
    if checkbytes != applicationheader:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'no valid %s header' % applicationname,
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## then read chunks
    while True:
        if brokenlength:
            if checkfile.tell() == offset + rifflength:
                break
        else:
            if checkfile.tell() == offset + rifflength + 8:
                break
        haspadding = False
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset + unpackedsize,
                              'reason': 'no valid chunk header',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        if not checkbytes in validchunkfourcc:
            checkfile.close()
            unpackingerror = {'offset': offset + unpackedsize,
                              'reason': 'no valid chunk FourCC %s' % checkbytes,
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then the chunk size
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
        unpackedsize += 4

        ## finally skip over the bytes in the file
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

    ## extra sanity check to see if the size of the unpacked data
    ## matches the declared size from the header.
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

    ## if the entire file is the RIFF file, then label it as such
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('riff')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
               'filesandlabels': unpackedfilesandlabels}

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked-%s" % applicationname.lower())
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    return {'status': True, 'length': unpackedsize, 'labels': labels,
           'filesandlabels': unpackedfilesandlabels}

## test files for ANI: http://www.anicursor.com/diercur.html
## http://fileformats.archiveteam.org/wiki/Windows_Animated_Cursor#Sample_files
def unpackANI(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []

    ## a list of valid ANI chunk FourCC
    validchunkfourcc = set([b'IART', b'ICON', b'INAM', b'LIST',
                            b'anih', b'rate', b'seq '])

    ## Some ANI files have a broken RIFF header, so try to
    ## detect if that is the case. This is not 100% foolproof.
    brokenlength = False

    ## Then read four bytes and check the length (stored
    ## in little endian format)
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    checkbytes = checkfile.read(4)
    rifflength = int.from_bytes(checkbytes, byteorder='little')
    if rifflength == filesize:
        brokenlength = True
    checkfile.close()

    unpackres = unpackRIFF(filename, offset, unpackdir, validchunkfourcc, 'ANI', b'ACON', filesize, brokenlength)
    if unpackres['status']:
        labels = copy.deepcopy(unpackres['labels'])
        if offset == 0 and unpackres['length'] == filesize:
            labels += ['ani', 'graphics']
        for u in unpackres['filesandlabels']:
            unpackedfilesandlabels.append((u, ['ani', 'graphics', 'unpacked']))
        return {'status': True, 'length': unpackres['length'],
                'filesandlabels': unpackedfilesandlabels, 'labels': labels}
    return {'status': False, 'error': unpackres['error']}

## PNG specifications can be found at:
##
## https://www.w3.org/TR/PNG/
##
## Section 5 describes the structure of a PNG file
def unpackPNG(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    if filesize - offset < 57:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 57 bytes'}
        return {'status': False, 'error': unpackingerror}

    ## open the file skip over the magic header bytes (section 5.2)
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+8)
    unpackedsize = 8

    ## Then process the PNG data. All data is in network byte order
    ## (section 7).
    ## First read the size of the first chunk, which is always 25 bytes
    ## when including length, chunk type and CRC fields (section 11.2.2)
    checkbytes = checkfile.read(25)
    if checkbytes[0:4] != b'\x00\x00\x00\x0d':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'no valid chunk length'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}

    ## The first chunk *has* to be IHDR
    if checkbytes[4:8] != b'IHDR':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'no IHDR header'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}

    ## then compute the CRC32 of bytes 4 - 21 (header + data)
    ## and compare it to the CRC in the PNG file
    crccomputed = binascii.crc32(checkbytes[4:21])
    crcstored = int.from_bytes(checkbytes[21:25], byteorder='big')
    if crccomputed != crcstored:
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'Wrong CRC'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 25

    ## Then move on to the next chunks in similar fashion (section 5.3)
    endoffilereached = False
    idatseen = False
    chunknames = set()
    while True:
        ## read the chunk size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            unpackingerror = {'offset': offset + unpackedsize,
                              'fatal': False,
                              'reason': 'Could not read chunk size'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}
        chunksize = int.from_bytes(checkbytes, byteorder='big')
        if offset + chunksize > filesize:
            unpackingerror = {'offset': offset + unpackedsize,
                              'fatal': False,
                              'reason': 'PNG data bigger than file'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## read the chunk type, plus the chunk data
        checkbytes = checkfile.read(4+chunksize)
        chunktype = checkbytes[0:4]
        if len(checkbytes) != 4+chunksize:
            unpackingerror = {'offset': offset + unpackedsize,
                              'fatal': False,
                              'reason': 'Could not read chunk type'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}

        unpackedsize += 4+chunksize

        ## compute the CRC
        crccomputed = binascii.crc32(checkbytes)
        checkbytes = checkfile.read(4)
        crcstored = int.from_bytes(checkbytes, byteorder='big')
        if crccomputed != crcstored:
            unpackingerror = {'offset': offset + unpackedsize,
                              'fatal': False, 'reason': 'Wrong CRC'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}

        ## add the name of the chunk to the list of chunk names
        chunknames.add(chunktype)
        if chunktype == b'IEND':
            ## IEND indicates the end of the file
            endoffilereached = True
            unpackedsize += 4
            break
        elif chunktype == b'IDAT':
            ## a valid PNG file has to have a IDAT section
            idatseen = True
        unpackedsize += 4

    ## There has to be at least 1 IDAT chunk (section 5.6)
    if not idatseen:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'No IDAT found'}
        return {'status': False, 'error': unpackingerror}

    ## Check whether or not the PNG is animated.
    ## https://wiki.mozilla.org/APNG_Specification
    animated = False
    if b'acTL' in chunknames and b'fcTL' in chunknames and b'fdAT' in chunknames:
        animated = True

    ## There has to be exactly 1 IEND chunk (section 5.6)
    if endoffilereached:
        if offset == 0 and unpackedsize == filesize:
            ## now load the file into PIL as an extra sanity check
            try:
                testimg = PIL.Image.open(checkfile)
                testimg.load()
                testimg.close()
            except Exception as e:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid PNG data according to PIL'}
                return {'status': False, 'error': unpackingerror}
            checkfile.close()
            labels += ['png', 'graphics']
            if animated:
                labels.append('animated')
                labels.append('apng')
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        ## else carve the file. It is anonymous, so just give it a name
        outfilename = os.path.join(unpackdir, "unpacked.png")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()

        ## reopen as read only
        outfile = open(outfilename, 'rb')

        ## now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(outfile)
            testimg.load()
            testimg.close()
            outfile.close()
        except:
            outfile.close()
            os.unlink(outfilename)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid PNG data according to PIL'}
            return {'status': False, 'error': unpackingerror}

        if animated:
            unpackedfilesandlabels.append((outfilename, ['png', 'graphics', 'animated', 'apng', 'unpacked']))
        else:
            unpackedfilesandlabels.append((outfilename, ['png', 'graphics', 'unpacked']))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## There is no end of file, so it is not a valid PNG.
    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'No IEND found'}
    return {'status': False, 'error': unpackingerror}

## Derived from public gzip specifications and Python module documentation
## The gzip format is described in RFC 1952
## https://tools.ietf.org/html/rfc1952
## sections 2.2 and 2.3
##
## gzip uses zlib's DEFLATE which is documented in RFC 1951
## https://tools.ietf.org/html/rfc1951
##
## Python's gzip module cannot be used, as it cannot correctly process
## gzip data if there is other non-gzip data following the gzip compressed
## data, so it has to be processed another way.
def unpackGzip(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## treat CRC errors as fatal
    wrongcrcfatal = True

    checkfile = open(filename, 'rb')
    checkfile.seek(offset+3)
    unpackedsize += 3
    ## RFC 1952 http://www.zlib.org/rfc-gzip.html describes the flags,
    ## but omits the "encrytion" flag (bit 5)
    ##
    ## Python 3's zlib module does not support:
    ## * continuation of multi-part gzip (bit 2)
    ## * encrypt (bit 5)
    ##
    ## RFC 1952 says that bit 6 and 7 should not be set
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}
    if (checkbytes[0] >> 2 & 1) == 1:
        ## continuation of multi-part gzip
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported multi-part gzip'}
        return {'status': False, 'error': unpackingerror}
    if (checkbytes[0] >> 5 & 1) == 1:
        ## encrypted
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported encrypted'}
        return {'status': False, 'error': unpackingerror}
    if (checkbytes[0] >> 6 & 1) == 1 or (checkbytes[0] >> 7 & 1) == 1:
        ## reserved
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not a valid gzip file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    havecrc16 = False
    ## if bit on is set then there is a CRC16
    if (checkbytes[0] >> 1 & 1) == 1:
        havecrc16 = True

    havefextra = False
    ## if bit two is set then there is extra info
    if (checkbytes[0] >> 2 & 1) == 1:
        havefextra = True

    havefname = False
    ## if bit three is set then there is a name
    if (checkbytes[0] >> 3 & 1) == 1:
        havefname = True

    havecomment = False
    ## if bit four is set then there is a comment
    if (checkbytes[0] >> 4 & 1) == 1:
        havecomment = True

    ## skip over the MIME field
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## skip over the XFL and OS fields
    checkfile.seek(2,os.SEEK_CUR)
    unpackedsize += 2

    ## optional XLEN
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
        unpackedsize +=  xlen + 2

    ## extract the original file name, if any
    ## This can be used later to rename the file. Because of
    ## false positives the name cannot be checked now.
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

   ## then extract the comment
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
    #origcomment = origcomment.decode()

    ## skip over the CRC16, if present
    if havecrc16:
        checkfile.seek(2,os.SEEK_CUR)
        unpackedsize += 2

    ## next are blocks of zlib compressed data
    ## RFC 1951 section 3.2.3 describes the algorithm and also
    ## an extra sanity check.
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

    ## go back one byte
    checkfile.seek(-1,os.SEEK_CUR)

    ## what follows next is raw deflate blocks. To unpack raw deflate
    ## data the windowBits have to be set to negative values:
    ## http://www.zlib.net/manual.html#Advanced
    ## First create a zlib decompressor that can decompress raw deflate
    ## https://docs.python.org/3/library/zlib.html#zlib.compressobj
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

    ## now start decompressing the data
    ## set the name of the file in case it is "anonymous data"
    ## otherwise just imitate whatever gunzip does. If the file has a
    ## name recorded in the file it will be renamed later.
    if filename.suffix.lower() == '.gz':
        outfilename = os.path.join(unpackdir, filename.stem)
    else:
        outfilename = os.path.join(unpackdir, "unpacked-from-gz")

    ## open a file to write any unpacked data to
    outfile = open(outfilename, 'wb')

    ## store the CRC of the uncompressed data
    gzipcrc32 = zlib.crc32(b'')

    ## then continue
    readsize = 10000000
    checkbytes = bytearray(readsize)
    while True:
        checkfile.readinto(checkbytes)
        try:
            unpackeddata = decompressor.decompress(checkbytes)
            outfile.write(unpackeddata)
            gzipcrc32 = zlib.crc32(unpackeddata, gzipcrc32)
        except Exception as e:
            ## clean up
            outfile.close()
            os.unlink(os.path.join(unpackdir, outfilename))
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'File not a valid gzip file'}
            return {'status': False, 'error': unpackingerror}

        unpackedsize += len(checkbytes) - len(decompressor.unused_data)
        if decompressor.unused_data != b'':
            break
    outfile.close()

    ## A valid gzip file has CRC32 and ISIZE at the end, so there should
    ## always be at least 8 bytes left for a valid file.
    if filesize - unpackedsize + offset < 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no CRC and ISIZE'}
        return {'status': False, 'error': unpackingerror}

    ## first reset the file pointer until the end of the unpacked zlib data
    checkfile.seek(offset + unpackedsize)

    ## now compute the gzip CRC of the uncompressed data and compare to
    ## the CRC stored in the file (RFC 1952, section 2.3.1)
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    if not gzipcrc32 == int.from_bytes(checkbytes, byteorder='little') and wrongcrcfatal:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong CRC'}
        return {'status': False, 'error': unpackingerror}

    ## compute the ISIZE (RFC 1952, section 2.3.1)
    checkbytes = checkfile.read(4)
    checkfile.close()

    unpackedsize += 4

    ## this check is modulo 2^32
    isize = os.stat(outfilename).st_size % pow(2,32)
    if int.from_bytes(checkbytes, byteorder='little') != isize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for ISIZE'}
        return {'status': False, 'error': unpackingerror}

    ## now rename the file in case the file name was known
    if havefname:
        if len(origname) != 0:
            origname = origname.decode()
            ## in this case report the original name as well in a
            ## different data structure
            try:
                shutil.move(outfilename, os.path.join(unpackdir, origname))
                outfilename = os.path.join(unpackdir, origname)
            except:
                pass

    ## add the unpacked file to the result list
    unpackedfilesandlabels.append((outfilename, []))

    ## if the whole file is the gzip file add some more labels
    if offset == 0 and offset + unpackedsize == filesize:
        labels += ['gzip', 'compressed']

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://en.wikipedia.org/wiki/BMP_file_format
def unpackBMP(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    ## first check if the data is large enough
    ## BMP header is 14 bytes, smallest DIB header is 12 bytes
    ## https://en.wikipedia.org/wiki/BMP_file_format#Bitmap_file_header
    if filesize - offset < 26:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 26 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename, 'rb')
    ## skip over the magic
    checkfile.seek(offset+2)
    unpackedsize += 2

    ## then extract the declared size of the BMP
    checkbytes = checkfile.read(4)
    bmpsize = int.from_bytes(checkbytes, byteorder='little')
    if offset + bmpsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for BMP file'}
        return {'status': False, 'error': unpackingerror}

    ## skip over 4 bytes of reserved data
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## read the offset of the BMP data
    checkbytes = checkfile.read(4)
    bmpoffset = int.from_bytes(checkbytes, byteorder='little')

    ## the BMP offset cannot be bigger than the bmpsize
    if bmpoffset > bmpsize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'BMP offset cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## read the first two bytes of the DIB header (DIB header size) as
    ## an extra sanity check.  There are actually just a few supported
    ## values:
    ## https://en.wikipedia.org/wiki/BMP_file_format#DIB_header_(bitmap_information_header)
    checkbytes = checkfile.read(2)
    dibheadersize = int.from_bytes(checkbytes, byteorder='little')
    if not dibheadersize in set([12, 64, 16, 40, 52, 56, 108, 124]):
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid DIB header'}
        return {'status': False, 'error': unpackingerror}

    ## check if the header size is inside the file
    if offset + 14 + dibheadersize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for DIB header'}
        return {'status': False, 'error': unpackingerror}

    ## the BMP data offset is from the start of the BMP file. It cannot
    ## be inside the BMP header (14 bytes) or the DIB header (variable).
    if bmpoffset < dibheadersize + 14:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid BMP data offset'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    if offset == 0 and bmpsize == filesize:
        ## now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid BMP according to PIL'}
            return {'status': False, 'error': unpackingerror}
        checkfile.close()

        labels.append('bmp')
        labels.append('graphics')
        return {'status': True, 'length': bmpsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    outfilename = os.path.join(unpackdir, "unpacked.bmp")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, bmpsize)
    outfile.close()
    checkfile.close()

    ## open as read only
    outfile = open(outfilename, 'rb')

    ## now load the file into PIL as an extra sanity check
    try:
        testimg = PIL.Image.open(outfile)
        testimg.load()
        testimg.close()
        outfile.close()
    except:
        outfile.close()
        os.unlink(outfilename)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid BMP data according to PIL'}
        return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfilename, ['bmp', 'graphics', 'unpacked']))
    return {'status': True, 'length': bmpsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## wrapper for LZMA, with a few extra sanity checks based on
## LZMA format specifications.
def unpackLZMA(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    if filesize - offset < 13:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}

    ## There are many false positives for LZMA.
    ## The file lzma-file-format.txt in XZ file distributions describe
    ## the LZMA format. The first 13 bytes describe the header. The last
    ## 8 bytes of the header describe the file size.
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+5)
    checkbytes = checkfile.read(8)
    checkfile.close()

    ## first check if an actual length of the *uncompressed* data is
    ## stored, or if it is possibly stored as a stream. LZMA streams
    ## have 0xffffffff stored in the length field.
    ## http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
    if checkbytes != b'\xff\xff\xff\xff\xff\xff\xff\xff':
        lzmaunpackedsize = int.from_bytes(checkbytes, byteorder='little')
        if lzmaunpackedsize == 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'declared size 0'}
            return {'status': False, 'error': unpackingerror}

        ## XZ Utils cannot unpack or create files > 256 GiB
        if lzmaunpackedsize > 274877906944:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'declared size too big'}
            return {'status': False, 'error': unpackingerror}
    else:
        lzmaunpackedsize = -1

    return unpackLZMAWrapper(filename, offset, unpackdir, '.lzma', 'lzma', 'LZMA', lzmaunpackedsize)

## wrapper for both LZMA and XZ
## Uses standard Python code.
def unpackLZMAWrapper(filename, offset, unpackdir, extension, filetype, ppfiletype, lzmaunpackedsize):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    unpackedsize = 0
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)

    ## Extract one 900k block of data as an extra sanity check.
    ## First create a decompressor
    decompressor = lzma.LZMADecompressor()
    checkdata = checkfile.read(900000)

    ## then try to decompress the data.
    try:
        unpackeddata = decompressor.decompress(checkdata)
    except Exception:
        ## no data could be successfully unpacked
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not valid %s data' % ppfiletype}
        return {'status': False, 'error': unpackingerror}

    ## set the name of the file in case it is "anonymous data"
    ## otherwise just imitate whatever unxz and lzma do. If the file
    ## has a name recorded in the file it will be renamed later.
    if filetype == 'xz' and filename.suffix.lower() == '.xz':
       outfilename = os.path.join(unpackdir, filename.stem)
    elif filetype == 'lzma' and filename.suffix.lower() == '.lzma':
       outfilename = os.path.join(unpackdir, filename.stem)
    else:
        outfilename = os.path.join(unpackdir, "unpacked-from-%s" % filetype)

    ## data has been unpacked, so open a file and write the data to it.
    ## unpacked, or if all data has been unpacked
    outfile = open(outfilename, 'wb')
    outfile.write(unpackeddata)
    unpackedsize += len(checkdata) - len(decompressor.unused_data)

    ## there is still some data left to be unpacked, so
    ## continue unpacking, as described in the Python documentation:
    ## https://docs.python.org/3/library/bz2.html#incremental-de-compression
    ## https://docs.python.org/3/library/lzma.html
    ## read some more data in chunks of 10 MB
    datareadsize = 10000000
    checkdata = checkfile.read(datareadsize)
    while checkdata != b'':
        try:
            unpackeddata = decompressor.decompress(checkdata)
        except EOFError as e:
            break
        except Exception as e:
            ## clean up
            outfile.close()
            os.unlink(outfilename)
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'File not a valid %s file' % ppfiletype}
            return {'status': False, 'error': unpackingerror}
        outfile.write(unpackeddata)
        ## there is no more compressed data
        unpackedsize += len(checkdata) - len(decompressor.unused_data)
        if decompressor.unused_data != b'':
            break
        checkdata = checkfile.read(datareadsize)
    outfile.close()
    checkfile.close()

    ## ignore empty files, as it is bogus data
    if os.stat(outfilename).st_size == 0:
        os.unlink(outfilename)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'File not a valid %s file' % ppfiletype}
        return {'status': False, 'error': unpackingerror}

    ## check if the length of the unpacked LZMA data is correct, but
    ## only if any unpacked length has been defined.
    if filetype == 'lzma' and lzmaunpackedsize != -1:
        if lzmaunpackedsize != os.stat(outfilename).st_size:
            os.unlink(outfilename)
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'length of unpacked %s data does not correspond with header' % ppfiletype}
            return {'status': False, 'error': unpackingerror}

    min_lzma = 256

    ## LZMA sometimes has bogus files filled with 0x00
    if os.stat(outfilename).st_size < min_lzma:
        pass

    if offset == 0 and unpackedsize == filesize:
        ## in case the file name ends in extension rename the file
        ## to mimic the behaviour of "unxz" and similar
        if filename.suffix.lower() == extension:
            newoutfilename = os.path.join(unpackdir, filename.stem)
            shutil.move(outfilename, newoutfilename)
            outfilename = newoutfilename
        labels += [filetype, 'compressed']
    unpackedfilesandlabels.append((outfilename, []))

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## XZ unpacking works just like LZMA unpacking
##
## XZ specifications:
##
## https://tukaani.org/xz/xz-file-format.txt
##
## XZ has some extra data (footer) that can be used for
## verifying the integrity of the file.
def unpackXZ(filename, offset, unpackdir, temporarydirectory):
    return unpackLZMAWrapper(filename, offset, unpackdir, '.xz', 'xz', 'XZ', -1)

## timezone files
## Format is documented in the Linux man pages:
##
## man 5 tzfile
##
## or an up to date version:
##
## http://man7.org/linux/man-pages/man5/tzfile.5.html
##
## in case the distribution man page does not cover version
## 3 of the timezone file format.
def unpackTimeZone(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    if filesize - offset < 44:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip the offset
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## read the version
    checkbytes = checkfile.read(1)
    if checkbytes == b'\x00':
        version = 0
    elif checkbytes == b'\x32':
        version = 2
    elif checkbytes == b'\x33':
        version = 3
    else:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## then 15 NUL bytes
    checkbytes = checkfile.read(15)
    if checkbytes != b'\x00' * 15:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved bytes not 0'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 15

    ## then the number of UT/local indicators in "standard byte order"
    ## (big endian)
    checkbytes = checkfile.read(4)
    ut_indicators = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## then the number of standard/wall indicators
    checkbytes = checkfile.read(4)
    standard_indicators = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## the number of leap seconds for which data entries are stored
    checkbytes = checkfile.read(4)
    leap_cnt = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## the number of transition times for which data entries are stored
    checkbytes = checkfile.read(4)
    transition_times = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## the number of local time types (must not be zero)
    checkbytes = checkfile.read(4)
    local_times = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4
    if local_times == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'local of times set to not-permitted 0'}
        return {'status': False, 'error': unpackingerror}

    ## the number of bytes of timezone abbreviation strings
    checkbytes = checkfile.read(4)
    tz_abbrevation_bytes = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    for i in range(0, transition_times):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for transition time'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

    ## then a number of bytes, each serving as an index into
    ## the next field.
    for i in range(0, transition_times):
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for transition time'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
        if ord(checkbytes) > local_times:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid index for transition time'}
            return {'status': False, 'error': unpackingerror}

    ## now read a bunch of ttinfo entries
    for i in range(0, local_times):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ttinfo GMT offsets'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then the DST flag byte
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ttinfo DST info'}
            return {'status': False, 'error': unpackingerror}
        if not (ord(checkbytes) == 0 or ord(checkbytes) == 1):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid value for ttinfo DST info'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

        ## then the abbreviation index, which points into the
        ## abbrevation strings, so cannot be larger than than tz_abbrevation_bytes
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ttinfo abbreviation index'}
            return {'status': False, 'error': unpackingerror}
        if ord(checkbytes) > tz_abbrevation_bytes:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid value for ttinfo abbreviation index'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    ## then the abbrevation strings, as indicated by tz_abbrevation_bytes
    checkbytes = checkfile.read(tz_abbrevation_bytes)
    if len(checkbytes) != tz_abbrevation_bytes:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for abbreviation bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += tz_abbrevation_bytes

    ## then 2 pairs of 4 bytes for each of the leap second entries
    for i in range(0, leap_cnt):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for leap seconds'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for leap seconds'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

    ## then one byte for each of the standard/wall indicators
    for i in range(0, standard_indicators):
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for standard indicator'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    ## then one byte for each of the UT/local indicators
    for i in range(0, ut_indicators):
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for UT indicator'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    ## This is the end for version 0 timezone files
    if version == 0:
        if offset == 0 and unpackedsize == filesize:
            checkfile.close()
            labels.append('resource')
            labels.append('timezone')
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}
        ## else carve the file
        outfilename = os.path.join(unpackdir, "unpacked-from-timezone")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfilename, ['timezone', 'resource', 'unpacked']))
        checkfile.close()
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## Then continue with version 2 data. The header is identical to the
    ## version 1 header.
    if offset + unpackedsize + 44 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for version 2 timezone header'}
        return {'status': False, 'error': unpackingerror}

    ## first check the header
    checkbytes = checkfile.read(4)
    if checkbytes != b'TZif':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid magic for version 2 header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## read the version
    checkbytes = checkfile.read(1)
    if checkbytes == b'\x32':
        newversion = 2
    elif checkbytes == b'\x33':
        newversion = 3
    else:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid version'}
        return {'status': False, 'error': unpackingerror}

    ## The version has to be identical to the previously declard version
    if version != newversion:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'versions in headers don\'t match'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## then 15 NUL bytes
    checkbytes = checkfile.read(15)
    if checkbytes != b'\x00' * 15:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved bytes not 0'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 15

    ## then the number of UT/local indicators in "standard byte order" (big endian)
    checkbytes = checkfile.read(4)
    ut_indicators = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## then the number of standard/wall indicators
    checkbytes = checkfile.read(4)
    standard_indicators = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## the number of leap seconds for which data entries are stored
    checkbytes = checkfile.read(4)
    leap_cnt = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## the number of transition times for which data entries are stored
    checkbytes = checkfile.read(4)
    transition_times = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## the number of local time types (must not be zero)
    checkbytes = checkfile.read(4)
    local_times = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4
    if local_times == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'local of times set to not-permitted 0'}
        return {'status': False, 'error': unpackingerror}

    ## the number of bytes of timezone abbreviation strings
    checkbytes = checkfile.read(4)
    tz_abbrevation_bytes = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    for i in range(0, transition_times):
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for transition time'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 8

    ## then a number of bytes, each serving as an index into
    ## the next field.
    for i in range(0, transition_times):
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for transition time'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
        if ord(checkbytes) > local_times:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid index for transition time'}
            return {'status': False, 'error': unpackingerror}

    ## now read a bunch of ttinfo entries
    for i in range(0, local_times):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ttinfo GMT offsets'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then the DST flag byte
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ttinfo DST info'}
            return {'status': False, 'error': unpackingerror}
        if not (ord(checkbytes) == 0 or ord(checkbytes) == 1):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid value for ttinfo DST info'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

        ## then the abbreviation index, which points into the
        ## abbrevation strings, so cannot be larger than
        ## tz_abbrevation_bytes
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ttinfo abbreviation index'}
            return {'status': False, 'error': unpackingerror}
        if ord(checkbytes) > tz_abbrevation_bytes:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid value for ttinfo abbreviation index'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    ## then the abbrevation strings, as indicated by tz_abbrevation_bytes
    checkbytes = checkfile.read(tz_abbrevation_bytes)
    if len(checkbytes) != tz_abbrevation_bytes:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for abbreviation bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += tz_abbrevation_bytes

    ## then 2 pairs of 4 bytes for each of the leap second entries
    for i in range(0, leap_cnt):
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for leap seconds'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 8

        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for leap seconds'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

    ## then one byte for each of the standard/wall indicators
    for i in range(0, standard_indicators):
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for standard indicator'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    ## then one byte for each of the UT/local indicators
    for i in range(0, ut_indicators):
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for UT indicator'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    ## next comes a POSIX-TZ-environment-variable-style string
    ## (possibly empty) enclosed by newlines
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for POSIX TZ environment style string'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'\n':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for POSIX TZ environment style string'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## read until an enclosing newline is found
    ## valid chars can be found in the tzset(3) manpage
    ##
    ## $ man 3 tzset
    ##
    ## and is basically a subset of string.printable (no spaces,
    ## and less punctuation)
    ## The version 3 extensions are simply a change to this string
    ## so it is already covered.
    while True:
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'enclosing newline for POSIX TZ environment style string not found'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
        if checkbytes == b'\n':
            break
        if not chr(ord(checkbytes)) in string.printable or chr(ord(checkbytes)) in string.whitespace:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid character in POSIX TZ environment style string'}
            return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('resource')
        labels.append('timezone')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    outfilename = os.path.join(unpackdir, "unpacked-from-timezone")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    unpackedfilesandlabels.append((outfilename, ['timezone', 'resource', 'unpacked']))
    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## unpacker for tar files. Uses the standard Python library.
## https://docs.python.org/3/library/tarfile.html
def unpackTar(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## tar is a concatenation of files. It could be that a tar file has
    ## been cut halfway but it might still be possible to extract some
    ## data. Use a file object so it is possible to start tar unpacking
    ## at arbitrary positions in the file.
    checkfile = open(filename, 'rb')

    ## seek to the offset where the tar is supposed to start. According
    ## to the documentation it should be opened at offset 0, but this
    ## works too.
    checkfile.seek(offset)
    unpacktar = tarfile.open(fileobj=checkfile, mode='r')

    ## record if something was unpacked and if something went wrong
    tarunpacked = False
    tarerror = False

    ## keep track of which file names were already
    ## unpacked. Files with the same name can be stored in a tar file
    ## as it is just a concetanation of files.
    ##
    ## Test tar files with the same file twice are easily made:
    ##
    ## $ tar cf test.tar /path/to/file
    ## $ tar --append -f test.tar /path/to/file
    unpackedtarfilenames = set()

    while True:
        ## store the name of the file unpacked. This is needed to clean
        ## up if something has gone wrong.
        tounpack = ''
        oldunpackedsize = checkfile.tell() - offset
        try:
            unpacktarinfo = unpacktar.next()
            if unpacktarinfo == None:
                break
            ## don't unpack block devices, character devices or FIFO
            ## https://docs.python.org/3/library/tarfile.html#tarfile.TarInfo.isdev
            if unpacktarinfo.isdev():
                continue
            tounpack = unpacktarinfo.name
            unpacktar.extract(unpacktarinfo, path=unpackdir, set_attrs=False)
            unpackedsize = checkfile.tell() - offset
            tarunpacked = True
            unpackedname = os.path.join(unpackdir,unpacktarinfo.name)

            ## TODO: rename files properly with minimum chance of clashes
            if unpackedname in unpackedtarfilenames:
                pass

            unpackedtarfilenames.add(unpackedname)
            if unpacktarinfo.isreg() or unpacktarinfo.isdir():
                ## tar changes permissions after unpacking, so change
                ## them back to something a bit more sensible
                os.chmod(unpackedname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
                if not os.path.isdir(unpackedname):
                    unpackedfilesandlabels.append((os.path.join(unpackdir, unpacktarinfo.name), []))
                elif unpacktarinfo.issym():
                    unpackedfilesandlabels.append((os.path.join(unpackdir, unpacktarinfo.name), ['symbolic link']))
                tounpack = ''
        except Exception as e:
            unpackedsize = oldunpackedsize
            tarerror = True
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': str(e)}
            if tounpack != '':
                unpackedname = os.path.join(unpackdir,unpackedname)
                if not os.path.islink(unpackedname):
                    os.chmod(unpackedname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
                if os.path.isdir(unpackedname) and not os.path.islink(unpackedname):
                    shutil.rmtree(unpackedname)
                else:
                    os.unlink(unpackedname)
            break

    ## first close the TarInfo object, then the underlying fileobj
    unpacktar.close()
    if not tarunpacked:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Not a valid tar file'}
        return {'status': False, 'error': unpackingerror}

    ## tar has finished, meaning it should also have read the termination
    ## blocks for the tar file, so set the unpacked size to just after
    ## where the tar module finished.
    unpackedsize = checkfile.tell() - offset

    ## Data was unpacked from the file, so the data up until now is
    ## definitely a tar, but is the rest of the file also part of the
    ## tar or of something else?
    ##
    ## Example: GNU tar tends to pad files with up to 20 blocks (512
    ## bytes each) filled with 0x00 although this heavily depends on
    ## the command line settings.
    ##
    ## This can be checked with GNU tar by inspecting the file with the
    ## options "itvRf" to the tar command:
    ##
    ## $ tar itvRf /path/to/tar/file
    ##
    ## These padding bytes are not read by Python's tarfile module and
    ## need to be explicitly checked and flagged as part of the file
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

## Unix portable archiver
## https://en.wikipedia.org/wiki/Ar_%28Unix%29
## https://sourceware.org/binutils/docs/binutils/ar.html
def unpackAr(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    unpackedsize = 0

    if offset != 0:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Currently only works on whole files'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('ar') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'ar program not found'}
        return {'status': False, 'error': unpackingerror}

    ## first test the file to see if it is a valid file
    p = subprocess.Popen(['ar', 't', filename], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (standard_out, standard_error) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid ar file'}
        return {'status': False, 'error': unpackingerror}

    ## then extract the file
    p = subprocess.Popen(['ar', 'x', filename], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=unpackdir)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        foundfiles = os.listdir(unpackdir)
        ## try to remove any files that were left behind
        for f in foundfiles:
            if os.path.isdir(os.path.join(unpackdir, f)):
                shutil.rmtree(os.path.join(unpackdir, f))
            else:
                os.unlink(os.path.join(unpackdir, f))

        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid ar file'}
        return {'status': False, 'error': unpackingerror}

    foundfiles = os.listdir(unpackdir)
    labels += ['archive', 'ar']

    foundfiles = os.listdir(unpackdir)
    for f in foundfiles:
       outputfilename = os.path.join(unpackdir, f)
       unpackedfilesandlabels.append((outputfilename, []))
       if f == 'debian-binary':
           if filename.suffix.lower() == '.deb' or filename.suffix.lower() == '.udeb':
               labels.append('debian')
               labels.append('deb')

    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Unpacking for squashfs
## There are many different flavours of squashfs and configurations
## differ per Linux distribution.
## This is for the "vanilla" squashfs, not for any vendor specific
## versions.
def unpackSquashfs(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    unpackedsize = 0

    if shutil.which('unsquashfs') == None:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'unsquashfs program not found'}
        return {'status': False, 'error': unpackingerror}

    ## need at least a header, plus version
    ## see /usr/share/magic
    if filesize - offset < 30:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    checkfile.seek(offset)

    ## sanity checks for the squashfs header.
    ## First determine the endianness of the file system.
    checkbytes = checkfile.read(4)
    if checkbytes == b'hsqs':
        bigendian = False
    else:
        bigendian = True

    ## then skip to the version, as this is an effective way to filter
    ## false positives.
    checkfile.seek(offset+28)
    checkbytes = checkfile.read(2)
    if bigendian:
        majorversion = int.from_bytes(checkbytes, byteorder='big')
    else:
        majorversion = int.from_bytes(checkbytes, byteorder='little')

    ## So far only squashfs 1-4 have been released (June 2018)
    if majorversion == 0 or majorversion > 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid squashfs version'}
        return {'status': False, 'error': unpackingerror}

    ## The location of the size of the squashfs file system depends
    ## on the major version of the file. These values can be found in
    ## /usr/share/magic or in the squashfs-tools source code
    ## ( squashfs_compat.h and squashfs_fs.h )
    if majorversion == 4:
        checkfile.seek(offset+40)
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data to read size'}
            return {'status': False, 'error': unpackingerror}
        if bigendian:
            squashfssize = int.from_bytes(checkbytes, byteorder='big')
        else:
            squashfssize = int.from_bytes(checkbytes, byteorder='little')
    elif majorversion == 3:
        checkfile.seek(offset+63)
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data to read size'}
            return {'status': False, 'error': unpackingerror}
        if bigendian:
            squashfssize = int.from_bytes(checkbytes, byteorder='big')
        else:
            squashfssize = int.from_bytes(checkbytes, byteorder='little')
    elif majorversion == 2:
        checkfile.seek(offset+8)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data to read size'}
            return {'status': False, 'error': unpackingerror}
        if bigendian:
            squashfssize = int.from_bytes(checkbytes, byteorder='big')
        else:
            squashfssize = int.from_bytes(checkbytes, byteorder='little')

    ## file size sanity check
    if offset + squashfssize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'file system cannot extend past file'}
        return {'status': False, 'error': unpackingerror}

    ## then create a temporary file and copy the data into the
    ## temporary file but only if offset != 0
    if offset != 0:
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        ## depending on the variant of squashfs a file size can be
        ## determined meaning less data needs to be copied.
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, filesize - offset)
        os.fdopen(temporaryfile[0]).close()
    checkfile.close()

    ## unpack in a temporary directory, as unsquashfs expects
    ## to create the directory itself, but the unpacking directory
    ## already exists.
    squashfsunpackdirectory = tempfile.mkdtemp(dir=temporarydirectory)

    if offset != 0:
        p = subprocess.Popen(['unsquashfs', temporaryfile[1]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=squashfsunpackdirectory)
    else:
        p = subprocess.Popen(['unsquashfs', filename],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=squashfsunpackdirectory)
    (outputmsg, errormsg) = p.communicate()

    if offset != 0:
        os.unlink(temporaryfile[1])

    if p.returncode != 0:
        shutil.rmtree(squashfsunpackdirectory)
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'Not a valid squashfs file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = squashfssize

    ## move contents of the unpacked file system
    foundfiles = os.listdir(squashfsunpackdirectory)
    if len(foundfiles) == 1:
        if foundfiles[0] == 'squashfs-root':
            os.chdir(os.path.join(squashfsunpackdirectory, 'squashfs-root'))
        else:
            os.chdir(squashfsunpackdirectory)
        listoffiles = os.listdir()
        for l in listoffiles:
            shutil.move(l, unpackdir,copy_function=local_copy2)

    ## clean up the temporary directory
    shutil.rmtree(squashfsunpackdirectory)

    ## now add everything that was unpacked
    dirwalk = os.walk(unpackdir)
    for direntries in dirwalk:
        ## make sure all subdirectories and files can be accessed
        for entryname in direntries[1]:
            fullfilename = os.path.join(direntries[0], entryname)
            if not os.path.islink(fullfilename):
                os.chmod(fullfilename, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
            unpackedfilesandlabels.append((fullfilename, []))
        for entryname in direntries[2]:
            fullfilename = os.path.join(direntries[0], entryname)
            unpackedfilesandlabels.append((fullfilename, []))

    if offset + unpackedsize != filesize:
        ## by default mksquashfs pads to 4K blocks with NUL bytes.
        ## The padding is not counted in squashfssize
        checkfile = open(filename, 'rb')
        checkfile.seek(offset + unpackedsize)
        padoffset = checkfile.tell()
        if unpackedsize % 4096 != 0:
            paddingbytes = 4096 - unpackedsize%4096
            checkbytes = checkfile.read(paddingbytes)
            if len(checkbytes) == paddingbytes:
                if checkbytes == paddingbytes * b'\x00':
                    unpackedsize += paddingbytes
                    havepadding = True
        checkfile.close()

    if offset == 0 and unpackedsize == filesize:
        labels.append('squashfs')
        labels.append('file system')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## a wrapper around shutil.copy2 to copy symbolic links instead of
## following them and copying the data. This is used in squashfs
## unpacking amongst others.
def local_copy2(src, dest):
    return shutil.copy2(src, dest, follow_symlinks=False)

## https://tools.ietf.org/html/rfc1740
## file format is described in appendices A & B
## test files: any ZIP file unpacked on MacOS X which
## has a directory called "__MACOSX"
## Files starting with ._ are likely AppleDouble encoded
def unpackAppleDouble(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    checkfile = open(filename, 'rb')
    ## skip over the offset
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then the version number, skip
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not a valid Apple Double file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## then 16 filler bytes, all 0x00 according to the specifications
    ## but not in files observed in real life.
    checkbytes = checkfile.read(16)
    if len(checkbytes) != 16:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough filler bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 16

    ## then the number of entries
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no number of entries'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## the number of entries, 0 or more, immediately
    ## following the header
    appledoubleentries = int.from_bytes(checkbytes, byteorder='big')

    ## having 0 entries does not make practical sense
    if appledoubleentries == 0:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no Apple Double entries'}
        return {'status': False, 'error': unpackingerror}

    ## store maximum offset, because the RFC says:
    ## "The entries in the AppleDouble Header file can appear in any order"
    maxoffset = unpackedsize

    for i in range(0,appledoubleentries):
        ## first the entry id, which cannot be 0
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'incomplete entry'}
            return {'status': False, 'error': unpackingerror}
        if int.from_bytes(checkbytes, byteorder='big') == 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no valid entry id'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then the offset
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'incomplete entry'}
            return {'status': False, 'error': unpackingerror}

        ## offset cannot be outside of the file
        entryoffset = int.from_bytes(checkbytes, byteorder='big')
        if offset + entryoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then the size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'incomplete entry'}
            return {'status': False, 'error': unpackingerror}
        ## data cannot be outside of the file
        entrysize = int.from_bytes(checkbytes, byteorder='big')
        if offset + entryoffset + entrysize> filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        maxoffset = max(maxoffset, entrysize + entryoffset)

    unpackedsize = maxoffset

    ## the entire file is the Apple Double file
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('resource')
        labels.append('appledouble')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked-from-appledouble")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['appledouble', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## ICC color profile
## Specifications: www.color.org/specification/ICC1v43_2010-12.pdf
## chapter 7.
##
## There are references throughout the code to ICC.1:2010, plus section
## numbers.
##
## Older specifications: http://www.color.org/icc_specs2.xalter
##
## Test files in package "colord" on for example Fedora
def unpackICC(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## ICC.1:2010, section 7.1
    if filesize - offset < 128:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid ICC file'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    checkfile.seek(offset)

    ## Then analyze the rest of the file
    ## all numbers are big endian (ICC.1:2010, 7.1.2)

    ## first the profile size, ICC.1:2010, 7.2.2
    ## The ICC file can never be bigger than the profile size
    checkbytes = checkfile.read(4)
    profilesize = int.from_bytes(checkbytes, byteorder='big')
    if offset + profilesize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not enough data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## CMM field ICC.1:2010, 7.2.3, skip for now, as valid information
    ## is in an online registry at www.color.org, so checks cannot
    ## be hardcoded.
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## profile version field, ICC.1:2010, 7.2.4, skip for now
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## profile/device class field, ICC.1:2010 7.2.5
    profilefields = [b'scnr', b'mntr', b'prtr', b'link',
                     b'spac', b'abst', b'nmcl']

    checkbytes = checkfile.read(4)
    if not checkbytes in profilefields:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid profile/device class field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## data colour space field, ICC.1:2010, 7.2.6
    datacolourfields = [b'XYZ ', b'Lab ', b'Luv ', b'YCbr', b'Yxy ', b'RGB ',
                        b'GRAY', b'HSV ', b'HLS ', b'CMYK', b'CMY ', b'2CLR',
                        b'3CLR', b'4CLR', b'5CLR', b'6CLR', b'7CLR', b'8CLR',
                        b'9CLR', b'ACLR', b'BCLR', b'CCLR', b'DCLR', b'ECLR',
                        b'FCLR']
    checkbytes = checkfile.read(4)
    if not checkbytes in datacolourfields:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid profile/device class field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## PCS field, ICC.1:2010, 7.2.7, skip for now
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## date and time, ICC.1:2010, 7.2.8, skip for now
    checkfile.seek(12,os.SEEK_CUR)
    unpackedsize += 12

    ## signature, ICC.1:2010, 7.2.9, already read, so skip
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## primary platform field, ICC.1:2010, 7.2.10
    checkbytes = checkfile.read(4)
    if not checkbytes in [b'APPL', b'MSFT', b'SGI ',
                          b'SUNW', b'\x00\x00\x00\x00']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid profile/device class field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## last 28 bytes of header should be 0x00, ICC.1:2010, 7.2.19
    checkfile.seek(offset+100)
    unpackedsize = 100
    checkbytes = checkfile.read(28)

    if not checkbytes == b'\x00' * 28:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved bytes not \\x00'}
        return {'status': False, 'error': unpackingerror}

    ## skip to the tag table, ICC.1:2010, 7.3
    checkfile.seek(offset+128)
    unpackedsize = 128

    ## the first 4 bytes are the tag count, ICC.1:2010 7.3.2
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no tag table'}
        return {'status': False, 'error': unpackingerror}
    tagcount = int.from_bytes(checkbytes, byteorder='big')
    ## each tag is 12 bytes
    if offset + unpackedsize + 4 + tagcount * 12 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for tag table'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    maxtagoffset = 0
    for n in range(0,tagcount):
        checkbytes = checkfile.read(12)
        ## first four bytes for a tag are the tag signature,
        ## ICC.1:2010 7.3.3
        ## skip for now.

        ## next four bytes are the offset of the data, ICC.1:2010 7.3.4
        icctagoffset = int.from_bytes(checkbytes[4:8], byteorder='big')

        ## tag offset has to be on a 4 byte boundary
        if icctagoffset%4 != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid tag offset'}
            return {'status': False, 'error': unpackingerror}
        if offset + icctagoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'offset outside of file'}
            return {'status': False, 'error': unpackingerror}

        ## then the size of the data, ICC.1:2010 7.3.5
        icctagsize = int.from_bytes(checkbytes[8:12], byteorder='big')
        if offset + icctagoffset + icctagsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data'}
            return {'status': False, 'error': unpackingerror}
        ## add padding if necessary
        if icctagsize % 4 != 0:
            icctagsize += 4 - (icctagsize % 4)
        unpackedsize += 12

        maxtagoffset = max(maxtagoffset, offset + icctagoffset + icctagsize)

        ## the tag offset cannot be outside of the declared profile size
        if maxtagoffset - offset >  profilesize:
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

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked.icc")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, maxtagoffset - offset)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['icc', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
## Documenting version 6.3.4
## This method first verifies a file to see where the ZIP data
## starts and where it ends.
##
## Python's zipfile module starts looking at the end of the file
## for a central directory. If multiple ZIP files have been concatenated
## and the last ZIP file is at the end, then only this ZIP file
## will be unpacked by Python's zipfile module.
##
## A description of some of the underlying problems encountered
## when writing this code can be found here:
##
## http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html
def unpackZip(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## the ZIP file format is described in section 4.3.6
    ## the header is at least 30 bytes
    if filesize < 30:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    encrypted = False
    zip64 = False

    ## skip over the (local) magic
    ## and process like section 4.3.7
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)
    maxzipversion = 90

    seencentraldirectory = False
    inlocal = True
    seenzip64endofcentraldir = False

    ## store if there is an Android signing block:
    ## https://source.android.com/security/apksigning/v2
    androidsigning = False

    ## store the local file names to check if they appear in the
    ## central directory in the same order (optional)
    localfiles = []
    centraldirectoryfiles = []

    ## First there are file entries, followed by a central
    ## directory, possibly with other headers following/preceding
    while True:
        ## first read the header
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for ZIP entry header'}
            return {'status': False, 'error': unpackingerror}

        ## process everything that is not a local file header, but
        ## either a ZIP header or an Android signing signature.
        if checkbytes != b'\x50\x4b\x03\x04':
            inlocal = False
            unpackedsize += 4

            ## archive decryption header
            ## archive data extra field (section 4.3.11)
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
            ## check for the start of the central directory (section 4.3.12)
            elif checkbytes == b'\x50\x4b\x01\02':
                seencentraldirectory = True
                if checkfile.tell() + 46 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for end of central directory'}
                    return {'status': False, 'error': unpackingerror}

                ## skip 24 bytes in the header to the file name
                ## and extra field
                checkfile.seek(24,os.SEEK_CUR)
                unpackedsize += 24

                ## read the file name
                checkbytes = checkfile.read(2)
                filenamelength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                ## read the extra field length
                checkbytes = checkfile.read(2)
                extrafieldlength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                ## read the file comment length
                checkbytes = checkfile.read(2)
                filecommentlength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                ## skip 12 bytes in the central directory header
                checkfile.seek(12,os.SEEK_CUR)
                unpackedsize += 12

                ## read the file name
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
                    ## read the extra field
                    checkbytes = checkfile.read(extrafieldlength)
                    if len(checkbytes) != extrafieldlength:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for extra field in central directory'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += extrafieldlength

                if filecommentlength != 0:
                    ## read the file comment
                    checkbytes = checkfile.read(filecommentlength)
                    if len(checkbytes) != filecommentlength:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for extra field in central directory'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += filecommentlength

            ## check for digital signatures (section 4.3.13)
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

            ## check for ZIP64 end of central directory (section 4.3.14)
            elif checkbytes == b'\x50\x4b\x06\x06':
                if not seencentraldirectory:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'ZIP64 end of cental directory, but no central directory header'}
                    return {'status': False, 'error': unpackingerror}
                seenzip64endofcentraldir = True

                ## first read the size of the ZIP64 end of
                ## central directory (section 4.3.14.1)
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

                ## now skip over the rest of the data in the
                ## ZIP64 end of central directory
                checkfile.seek(zip64endofcentraldirectorylength, os.SEEK_CUR)
                unpackedsize += zip64endofcentraldirectorylength

            ## check for ZIP64 end of central directory locator
            ## (section 4.3.15)
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
                ## skip over the data
                checkfile.seek(16, os.SEEK_CUR)
                unpackedsize += 16

            ## check for of central directory (section 4.3.16)
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

                ## skip 16 bytes of the header
                checkfile.seek(16,os.SEEK_CUR)
                unpackedsize += 16

                ## read the ZIP comment length
                checkbytes = checkfile.read(2)
                zipcommentlength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2
                if zipcommentlength != 0:
                    ## read the file comment
                    checkbytes = checkfile.read(zipcommentlength)
                    if len(checkbytes) != zipcommentlength:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for extra field in central directory'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += zipcommentlength
                ## end of ZIP file reached, so break out of the loop
                break
            elif checkbytes == b'PK\x07\x08':
                if checkfile.tell() + 12 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for data descriptor'}
                    return {'status': False, 'error': unpackingerror}
                checkfile.seek(12,os.SEEK_CUR)
            else:
                ## then check to see if this is possibly an Android
                ## signing block
                ## https://source.android.com/security/apksigning/v2
                if androidsigning or checkbytes == b'\x00\x00\x00\x00':
                    ## first go back four bytes
                    checkfile.seek(-4, os.SEEK_CUR)
                    unpackedsize = checkfile.tell() - offset

                    ## then read 8 bytes for the APK signing block size
                    checkbytes = checkfile.read(8)
                    if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for Android signing block'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += 8
                    androidsigningsize = int.from_bytes(checkbytes, byteorder='little')

                    ## APK signing V3 might pad to 4096 bytes first, introduced in
                    ## https://android.googlesource.com/platform/tools/apksig/+/edf96cb79f533eb4255ee1b6aa2ba8bf9c1729b2
                    if androidsigningsize == 0:
                        checkfile.seek(4096 - unpackedsize % 4096, os.SEEK_CUR)
                        unpackedsize += 4096 - unpackedsize % 4096

                        ## then read 8 bytes for the APK signing block size
                        checkbytes = checkfile.read(8)
                        if len(checkbytes) != 8:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'not enough data for Android signing block'}
                            return {'status': False, 'error': unpackingerror}
                        unpackedsize += 8
                        androidsigningsize = int.from_bytes(checkbytes, byteorder='little')

                    if checkfile.tell() + androidsigningsize > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for Android signing block'}
                        return {'status': False, 'error': unpackingerror}

                    ## then skip over the signing block, except the
                    ## last 16 bytes to have an extra sanity check
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

        ## continue with the local file headers instead
        if checkbytes == b'\x50\x4b\x03\x04' and not inlocal:
            ## this should totally not happen in a valid
            ## ZIP file: local file headers should not be
            ## interleaved with other headers.
            break

        unpackedsize += 4

        ## minimal version needed. According to 4.4.3.2 the minimal
        ## version is 1.0 and the latest is 6.3. As new versions of
        ## PKZIP could be released this check should not be too strict.
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for local file header'}
            return {'status': False, 'error': unpackingerror}
        minversion = int.from_bytes(checkbytes, byteorder='little')
        if minversion < 10:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid ZIP version'}
            return {'status': False, 'error': unpackingerror}
        if minversion > maxzipversion:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'invalid ZIP version'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## then the "general purpose bit flag" (section 4.4.4)
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for general bit flag in local file header'}
            return {'status': False, 'error': unpackingerror}
        generalbitflag = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        ## check if the file is encrypted. If so it should be labeled
        ## as such, but not be unpacked.
        ## generalbitflag & 0x40 == 0x40 would be a check for
        ## strong encryption, but that has different length encryption
        ## headers and right now there are no test files for it, so
        ## leave it for now.
        if generalbitflag & 0x01 == 0x01:
            encrypted = True

        datadescriptor = False

        ## see if there is a data descriptor for regular files in the
        ## general purpose bit flag. This usually won't be set for
        ## directories although sometimes it is
        ## (example: framework/ext.jar from various Android versions)
        if generalbitflag & 0x08 == 0x08:
            datadescriptor = True

        ## then the compression method (section 4.4.5)
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for compression method in local file header'}
            return {'status': False, 'error': unpackingerror}
        compressionmethod = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        ## skip over the time fields (section 4.4.6)
        checkfile.seek(4, os.SEEK_CUR)
        if checkfile.tell() + 4 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for time fields in local file header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## skip over the CRC32 (section 4.4.7)
        if checkfile.tell() + 4 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for CRC32 in local file header'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(4, os.SEEK_CUR)
        unpackedsize += 4

        ## compressed size (section 4.4.8)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for compressed size in local file header'}
            return {'status': False, 'error': unpackingerror}
        compressedsize = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        ## uncompressed size (section 4.4.9)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for uncompressed size file header'}
            return {'status': False, 'error': unpackingerror}
        uncompressedsize = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        ## then the file name length (section 4.4.10)
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for filename length in local file header'}
            return {'status': False, 'error': unpackingerror}
        filenamelength = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        ## and the extra field length (section 4.4.11)
        ## There does not necessarily have to be any useful data
        ## in the extra field.
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

        ## then check the extra field. The most important is to check
        ## for any ZIP64 extension, as it contains updated values for
        ## the compressed size and uncompressed size (section 4.5)
        if extrafieldlength > 0:
            extrafields = checkfile.read(extrafieldlength)
        if extrafieldlength > 4:
            extrafieldcounter = 0
            while extrafieldcounter + 4 < extrafieldlength:
                ## section 4.6.1
                extrafieldheaderid = int.from_bytes(extrafields[extrafieldcounter:extrafieldcounter+2], byteorder='little')

                ## often found in the first entry in JAR files and
                ## Android APK files, but not mandatory.
                ## http://hg.openjdk.java.net/jdk7/jdk7/jdk/file/00cd9dc3c2b5/src/share/classes/java/util/jar/JarOutputStream.java#l46
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
                    ## ZIP64, section 4.5.3
                    ## according to 4.4.3.2 PKZIP 4.5 or later is
                    ## needed to unpack ZIP64 files.
                    if minversion < 45:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'wrong minimal needed version for ZIP64'}
                        return {'status': False, 'error': unpackingerror}
                    zip64uncompressedsize = int.from_bytes(extrafields[extrafieldcounter:extrafieldcounter+8], byteorder='little')
                    zip64compressedsize = int.from_bytes(extrafields[extrafieldcounter+8:extrafieldcounter+16], byteorder='little')
                    if compressedsize == 0xffffffff:
                        compressedsize = zip64compressedsize
                    if uncompressedsize == 0xffffffff:
                        uncompressedsize = zip64uncompressedsize
                extrafieldcounter += extrafieldheaderlength
        unpackedsize += extrafieldlength

        ## some sanity checks: file name, extra field and compressed
        ## size cannot extend past the file size
        locallength = 30 + filenamelength + extrafieldlength + compressedsize
        if offset + locallength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'data cannot be outside file'}
            return {'status': False, 'error': unpackingerror}

        ## keep track of if a data descriptor was searched and found
        ## This is needed if the length of the compressed size is set
        ## to 0, which can happen in certain cases (section 4.4.4, bit 3)
        ddfound = False
        ddsearched = False

        if (not localfilename.endswith(b'/') and compressedsize == 0) or datadescriptor:
            datastart = checkfile.tell()
            ## in case the length is not known it is very difficult
            ## to see where the data ends so it is needed to search for
            ## a signature. This can either be:
            ##
            ## * data descriptor header
            ## * local file header
            ## * central directory header
            ##
            ## Whichever is found first will be processed.
            while True:
                curpos = checkfile.tell()
                tmppos = -1
                checkbytes = checkfile.read(50000)
                newcurpos = checkfile.tell()
                if checkbytes == b'':
                    break
                if datadescriptor:
                    ddpos = checkbytes.find(b'PK\x07\x08')
                    if ddpos != -1:
                        ddsearched = True
                        ddfound = True
                        ## sanity check
                        checkfile.seek(curpos + ddpos + 8)
                        tmpcompressedsize = int.from_bytes(checkfile.read(4), byteorder='little')
                        if curpos + ddpos - datastart == tmpcompressedsize:
                            tmppos = ddpos
                localheaderpos = checkbytes.find(b'PK\x03\x04')
                if localheaderpos != -1 and (localheaderpos < tmppos or tmppos == -1):
                    ## In case the file that is stored is an empty
                    ## file, then there will be no data descriptor field
                    ## so just continue as normal.
                    if curpos + localheaderpos == datastart:
                        checkfile.seek(curpos)
                        break

                    ## if there is a data descriptor, then the 12
                    ## bytes preceding the next header are:
                    ## * crc32
                    ## * compressed size
                    ## * uncompressed size
                    ## section 4.3.9
                    if datadescriptor:
                        if curpos + localheaderpos - datastart > 12:
                            checkfile.seek(curpos + localheaderpos - 8)
                            tmpcompressedsize = int.from_bytes(checkfile.read(4), byteorder='little')
                            ## and return to the original position
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
                centraldirpos = checkbytes.find(b'PK\x01\x02')
                if centraldirpos != -1:
                    ## In case the file that is stored is an empty
                    ## file, then there will be no data descriptor field
                    ## so just continue as normal.
                    if curpos + centraldirpos == datastart:
                        checkfile.seek(curpos)
                        break

                    ## if there is a data descriptor, then the 12
                    ## bytes preceding the next header are:
                    ## * crc32
                    ## * compressed size
                    ## * uncompressed size
                    ## section 4.3.9
                    if datadescriptor:
                        if curpos + centraldirpos - datastart > 12:
                            checkfile.seek(curpos + centraldirpos - 8)
                            tmpcompressedsize = int.from_bytes(checkfile.read(4), byteorder='little')
                            ## and return to the original position
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
                                    ## and (again) return to the
                                    ## original position
                                    checkfile.seek(newcurpos)
                    else:
                        if tmppos == -1:
                            tmppos = centraldirpos
                        else:
                            tmppos = min(centraldirpos, tmppos)

                    checkfile.seek(newcurpos)

                    oldtmppos = tmppos
                    ## extra sanity check: see if the
                    ## file names are the same
                    origpos = checkfile.tell()
                    checkfile.seek(curpos + tmppos + 42)
                    checkfn = checkfile.read(filenamelength)
                    if localfilename != checkfn:
                        tmppos = oldtmppos
                    checkfile.seek(origpos)
                if tmppos != -1:
                    checkfile.seek(curpos + tmppos)
                    break

                ## have a small overlap the size of a possible header
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

        ## data descriptor follows the file data
        if datadescriptor and ddsearched and ddfound:
            possiblesignature = checkfile.read(4)
            if possiblesignature == b'PK\x07\x08':
                ddcrc = checkfile.read(4)
            else:
                ddcrc = possiblesignature
            ddcompressedsize = checkfile.read(4)
            if len(ddcompressedsize) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for compressed data field'}
                return {'status': False, 'error': unpackingerror}
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
                ## possibly do an extra sanity check here with the
                ## compressed and/or uncompressed size fields
                pass

    if not seencentraldirectory:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'no central directory found'}
        return {'status': False, 'error': unpackingerror}

    ## there should be as many entries in the local headers as in
    ## the central directory
    if len(localfiles) != len(centraldirectoryfiles):
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'mismatch between local file headers and central directory'}
        return {'status': False, 'error': unpackingerror}

    ## compute the difference between the local files and
    ## the ones in the central directory
    if len(set(localfiles).intersection(set(centraldirectoryfiles))) != len(set(localfiles)):
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'mismatch between names in local file headers and central directory'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = checkfile.tell() - offset
    if not encrypted:
        ## if the ZIP file is at the end of the file then the ZIP module
        ## from Python will do a lot of the heavy lifting.
        ## Malformed ZIP files that need a workaround exist:
        ## https://bugzilla.redhat.com/show_bug.cgi?id=907442
        if checkfile.tell() == filesize:
            carved = False
        else:
            ## else carve the file from the larger ZIP first
            temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
            os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
            os.fdopen(temporaryfile[0]).close()
            carved = True
        if not carved:
            ## seek to the right offset, even though that's
            ## not even necessary.
            checkfile.seek(offset)
        try:
            if not carved:
                unpackzipfile = zipfile.ZipFile(checkfile)
            else:
                unpackzipfile = zipfile.ZipFile(temporaryfile[1])
            zipfiles = unpackzipfile.namelist()
            zipinfolist = unpackzipfile.infolist()
            oldcwd = os.getcwd()
            os.chdir(unpackdir)

            ## check if there have been directories stored
            ## as regular files.
            faultyzipfiles = []
            for z in zipinfolist:
                if z.file_size == 0 and not z.is_dir() and z.external_attr & 0x10 == 0x10:
                    faultyzipfiles.append(z)
            if len(faultyzipfiles) == 0:
                unpackzipfile.extractall()
            else:
                for z in zipinfolist:
                    if z in faultyzipfiles:
                        ## create the directory
                        os.makedirs(os.path.join(unpackdir, z.filename), exist_ok=True)
                    else:
                        unpackzipfile.extract(z)
            os.chdir(oldcwd)
            unpackzipfile.close()

            for i in zipinfolist:
                unpackedfilesandlabels.append((os.path.join(unpackdir, i.filename), []))
            if offset == 0 and not carved:
                labels.append('compressed')
                labels.append('zip')
                if androidsigning:
                    labels.append('apk')
            if carved:
                os.unlink(temporaryfile[1])
            checkfile.close()
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}
        except zipfile.BadZipFile:
            checkfile.close()
            if carved:
                os.unlink(temporaryfile[1])
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'Not a valid ZIP file'}
            return {'status': False, 'error': unpackingerror}

    ## it is an encrypted file
    if offset == 0 and checkfile.tell() == filesize:
        checkfile.close()
        labels.append('compressed')
        labels.append('zip')
        labels.append('encrypted')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    targetfilename = os.path.join(unpackdir, 'encrypted.zip')
    targetfile = open(targetfilename, 'wb')
    os.sendfile(targetfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    targetfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((targetfilename, ['encrypted', 'zip', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Derived from public bzip2 specifications
## and Python module documentation
def unpackBzip2(filename, offset, unpackdir, temporarydirectory, dryrun=False):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 10:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 10 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)

    ## Extract one 900k block of data as an extra sanity check.
    ## First create a bzip2 decompressor
    bz2decompressor = bz2.BZ2Decompressor()
    bz2data = checkfile.read(900000)

    ## then try to decompress the data.
    try:
        unpackeddata = bz2decompressor.decompress(bz2data)
    except Exception:
        ## no data could be successfully unpacked,
        ## so close the file and exit.
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'File not a valid bzip2 file'}
        return {'status': False, 'error': unpackingerror}

    ## set the name of the file in case it is "anonymous data"
    ## otherwise just imitate whatever bunzip2 does.
    if filename.suffix.lower() == '.bz2':
        outfilename = os.path.join(unpackdir, filename.stem)
    else:
        outfilename = os.path.join(unpackdir, "unpacked-from-bz2")

    ## data has been unpacked, so open a file and write the data to it.
    ## unpacked, or if all data has been unpacked
    if not dryrun:
        outfile = open(outfilename, 'wb')
        outfile.write(unpackeddata)

    unpackedsize += len(bz2data) - len(bz2decompressor.unused_data)

    ## there is still some data left to be unpacked, so
    ## continue unpacking, as described in the Python documentation:
    ## https://docs.python.org/3/library/bz2.html#incremental-de-compression
    ## read some more data in chunks of 10 MB
    datareadsize = 10000000
    bz2data = checkfile.read(datareadsize)
    while bz2data != b'':
        try:
            unpackeddata = bz2decompressor.decompress(bz2data)
        except EOFError as e:
            break
        except Exception as e:
            ## clean up
            if not dryrun:
                outfile.close()
                os.unlink(os.path.join(unpackdir, outfilename))
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'File not a valid bzip2 file, use bzip2recover?'}
            return {'status': False, 'error': unpackingerror}

        if not dryrun:
            outfile.write(unpackeddata)

        ## there is no more compressed data
        unpackedsize += len(bz2data) - len(bz2decompressor.unused_data)
        if bz2decompressor.unused_data != b'':
            break
        bz2data = checkfile.read(datareadsize)

    checkfile.close()

    if not dryrun:
        outfile.close()

        if offset == 0 and unpackedsize == filesize:
            ## in case the file name ends in either bz2 or tbz2 (tar)
            ## rename the file to mimic the behaviour of "bunzip2"
            if filename.suffix.lower() == '.bz2':
                newoutfilename = os.path.join(unpackdir, filename.stem)
                shutil.move(outfilename, newoutfilename)
                outfilename = newoutfilename
            elif filename.suffix.lower() == '.tbz2':
                newoutfilename = os.path.join(unpackdir, filename.stem) + ".tar"
                shutil.move(outfilename, newoutfilename)
                outfilename = newoutfilename
            labels += ['bzip2', 'compressed']
        unpackedfilesandlabels.append((outfilename, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Derived from specifications at:
## https://github.com/mackyle/xar/wiki/xarformat
##
## Basically XAR is a header, a zlib compressed XML file describing
## where to find files and how they were compressed, and then the
## actual data (perhaps compressed).
##
## Compression depends on the options provided and the version of XAR being
## used. Fedora's standard version uses:
##
## * none
## * gzip (default, but it is actually zlib's DEFLATE)
## * bzip2
##
## Other versions (from Git) can also use:
## * xz
## * lzma
def unpackXAR(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    if filesize - offset < 28:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Too small for XAR file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename, 'rb')

    ## skip over the file magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## read the size field
    checkbytes = checkfile.read(2)
    headersize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    ## read the version field
    checkbytes = checkfile.read(2)
    unpackedsize += 2

    ## read the toc_length_compressed field
    checkbytes = checkfile.read(8)
    toc_length_compressed = int.from_bytes(checkbytes, byteorder='big')

    ## check that the table of contents (toc) is actually
    ## inside the file
    if offset + headersize + toc_length_compressed > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'file too small'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    ## read the toc_length_uncompressed field. Use this for
    ## sanity checking.
    checkbytes = checkfile.read(8)
    unpackedsize += 8
    toc_length_uncompressed = int.from_bytes(checkbytes, byteorder='big')

    ## read the cksum_alg field. In case it is 3 do some extra
    ## sanity checks.
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
        ## all the other checksum algorithms have a 28 byte header
        if headersize != 28:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong header size'}
            return {'status': False, 'error': unpackingerror}

    ## skip over the entire header
    checkfile.seek(offset+headersize)
    unpackedsize = headersize

    ## read the table of contents
    checkbytes = checkfile.read(toc_length_compressed)
    ## now decompress the table of contents
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

    ## the toc is an XML file, so parse it
    try:
        tocdom = xml.dom.minidom.parseString(toc)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'table of contents is not valid XML'}
        return {'status': False, 'error': unpackingerror}

    ## The interesting information is in the <file> element. As these
    ## can be nested (to resemble a directory tree) each element has
    ## to be looked at separately to see if there are any child elements
    ## that have files or other directories.

    ## The top level element should be <xar>
    if tocdom.documentElement.tagName != 'xar':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'table of contents is not a valid TOC for XAR'}
        return {'status': False, 'error': unpackingerror}

    ## there should be one single node called "toc". If not, it
    ## is a malformed XAR table of contents.
    havevalidtoc = False
    for i in tocdom.documentElement.childNodes:
        ## the childnodes of the element could also
        ## include text nodes, which are not interesting
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

    ## Then further traverse the DOM
    ## Since each element only has relative path information it is
    ## necessary to keep track of the directory structure.

    maxoffset = -1

    ## store the nodes to traverse from the DOM in a deque, and then
    ## pop from the left as it is much more efficient then using a list
    ## for that.
    ## First fill up the deque with the top level file nodes.
    nodestotraverse = collections.deque()
    for i in tocnode.childNodes:
        if i.nodeType == xml.dom.Node.ELEMENT_NODE:
            if i.tagName == 'file':
                nodestotraverse.append((i, ''))
            elif i.tagName == 'checksum':
                ## top level checksum should have a size field and offset
                for ic in i.childNodes:
                    if ic.nodeType == xml.dom.Node.ELEMENT_NODE:
                        if ic.tagName == 'offset':
                            ## traverse the child nodes
                            for dd in ic.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    checksumoffset = dd.data.strip()
                        elif ic.tagName == 'size':
                            ## traverse the child nodes
                            for dd in ic.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    checksumsize = dd.data.strip()
                try:
                    checksumoffset = int(checksumoffset)
                    checksumsize = int(checksumsize)
                except:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'XML bogus values'}
                    return {'status': False, 'error': unpackingerror}
                ## the checksum cannot be outside of the file
                if offset + unpackedsize + checksumoffset + checksumsize > filesize:
                    targetfile.close()
                    os.unlink(targetfilename)
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data'}
                    return {'status': False, 'error': unpackingerror}
                maxoffset = max(maxoffset, offset + unpackedsize + checksumoffset + checksumsize)

    while len(nodestotraverse) != 0:
        (nodetoinspect, nodecwd) = nodestotraverse.popleft()

        ## then inspect the contents of the node. Since it is not
        ## guaranteed in which order the elements appear in the XML
        ## file some information has to be kept first.
        nodename = None
        nodetype = None
        nodedata = None
        childfilenodes = []
        for i in nodetoinspect.childNodes:
            if i.nodeType == xml.dom.Node.ELEMENT_NODE:
                if i.tagName == 'type':
                    ## first find out if it is a file, or a directory
                    for cn in i.childNodes:
                        if cn.nodeType == xml.dom.Node.TEXT_NODE:
                            nodetype = cn.data.strip()
                    ## something went wrong here
                    if nodetype == None:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'missing file type in TOC'}
                        return {'status': False, 'error': unpackingerror}
                elif i.tagName == 'name':
                    ## grab the name of the entry and store it in
                    ## nodename.
                    for cn in i.childNodes:
                        if cn.nodeType == xml.dom.Node.TEXT_NODE:
                            nodename = cn.data.strip()
                elif i.tagName == 'file':
                    ## add children to be processed
                    childfilenodes.append(i)
                elif i.tagName == 'data':
                    ## any data that might be there for the file
                    nodedata = i

        ## remove any superfluous / characters. This should not happen
        ## with XAR but just in case...
        while nodename.startswith('/'):
            nodename = nodename[1:]

        if nodetype == 'directory':
            os.makedirs(os.path.join(unpackdir, nodecwd, nodename))
        elif nodetype == 'file':
            ## first create the file
            targetfilename = os.path.join(unpackdir, nodecwd, nodename)
            targetfile = open(targetfilename, 'wb')
            if nodedata != None:
                ## extract the data for the file:
                ## * compression method (called "encoding")
                ## * offset
                ## * length
                ## * archived checksum + type (compressed data)
                ## * extracted checksum + type (uncompressed data)
                compressionmethod = None
                datalength = 0 ## compressed
                datasize = 0 ## uncompressed
                dataoffset = 0
                archivedchecksum = None
                archivedchecksumtype = None
                extractedchecksum = None
                extractedchecksumtype = None
                for d in nodedata.childNodes:
                    if d.nodeType == xml.dom.Node.ELEMENT_NODE:
                        if d.tagName == 'encoding':
                            ## encoding is stored as an attribute
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
                            ## traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    dataoffset = dd.data.strip()
                        elif d.tagName == 'length':
                            ## traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    datalength = dd.data.strip()
                        elif d.tagName == 'size':
                            ## traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    datasize = dd.data.strip()
                        elif d.tagName == 'archived-checksum':
                            archivedchecksumtype = d.getAttribute('style')
                            ## traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    archivedchecksum = dd.data.strip()
                        elif d.tagName == 'extracted-checksum':
                            extractedchecksumtype = d.getAttribute('style')
                            ## traverse the child nodes
                            for dd in d.childNodes:
                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                    extractedchecksum = dd.data.strip()
                ## first some sanity checks
                try:
                    dataoffset = int(dataoffset)
                    datalength = int(datalength)
                except:
                    targetfile.close()
                    os.unlink(targetfilename)
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'bogus XML values'}
                    return {'status': False, 'error': unpackingerror}

                ## more sanity checks
                ## the file cannot be outside of the file
                if offset + unpackedsize + dataoffset + datalength > filesize:
                    targetfile.close()
                    os.unlink(targetfilename)
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data'}
                    return {'status': False, 'error': unpackingerror}

                checkhash = None

                ## create a hashing object for the uncompressed file
                if extractedchecksumtype in hashlib.algorithms_available:
                    checkhash = hashlib.new(extractedchecksumtype)

                ## seek to the beginning of the file
                checkfile.seek(offset+unpackedsize+dataoffset)
                if compressionmethod == 'none':
                    ## if no compression is used just write the bytes
                    ## to the target file immediately.
                    bytesread = 0
                    ## write in chunks of 10 MB
                    maxbytestoread = 10000000
                    while bytesread != datalength:
                        checkbytes = checkfile.read(min(maxbytestoread, datalength-bytesread))
                        targetfile.write(checkbytes)
                        bytesread += len(checkbytes)
                        if checkhash != None:
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
                            os.unlink(targetfilename)
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'compression method not supported'}
                            return {'status': False, 'error': unpackingerror}

                        bytesread = 0
                        ## read in chunks of 10 MB
                        maxbytestoread = 10000000
                        while bytesread != datalength:
                            checkbytes = checkfile.read(min(maxbytestoread, datalength-bytesread))
                            ## decompress the data and write it to
                            ## the target file
                            decompressedbytes = decompressor.decompress(checkbytes)
                            targetfile.write(decompressedbytes)
                            targetfile.flush()
                            bytesread += len(checkbytes)
                            if checkhash != None:
                                checkhash.update(decompressedbytes)

                        ## there shouldn't be any unused data
                        if decompressor.unused_data != b'':
                            targetfile.close()
                            os.unlink(targetfilename)
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'broken data'}
                            return {'status': False, 'error': unpackingerror}

                    except Exception as e:
                        targetfile.close()
                        os.unlink(targetfilename)
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'broken data'}
                        return {'status': False, 'error': unpackingerror}

                ## if there is a checksum compare it to the one that
                ## was stored in the file.
                if checkhash != None:
                    if extractedchecksum != checkhash.hexdigest():
                        targetfile.close()
                        os.unlink(targetfilename)
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'checksum mismatch'}
                        return {'status': False, 'error': unpackingerror}

                unpackedfilesandlabels.append((targetfilename, []))
            else:
                ## empty files have no data section associated with it
                unpackedfilesandlabels.append((targetfilename, ['empty']))
            targetfile.close()
            maxoffset = max(maxoffset, offset + unpackedsize + dataoffset + datalength)
        ## then finally add all of the childnodes
        ## which is only happening for subdirectories anyway
        for cn in childfilenodes:
            nodestotraverse.append((cn, os.path.join(nodecwd, nodename)))

    checkfile.close()
    unpackedsize = maxoffset - offset
    if offset == 0 and maxoffset == filesize:
        labels += ['archive', 'xar']
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## GIF unpacker for the GIF87a and GIF89a formats. The specification
## can be found at:
##
## https://www.w3.org/Graphics/GIF/spec-gif89a.txt
##
## The references in the comments correspond to sections in this
## document.
## A grammer for the GIF format is described in Appendix B.
def unpackGIF(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## a minimal GIF file is 6 + 6 + 6 + 1 = 19
    if filesize - offset < 19:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'incompatible terminator records mixed'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip the offset (section 17)
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+6)
    unpackedsize += 6

    ## After the header comes a logical screen which
    ## consists of a logical screen descriptor (section 18)
    ## and an optional global color table (section 19)
    ## Only one logical screen descriptor is allowed per file.
    ## The logical screen descriptor is 6 bytes.
    ## All data is little endian (section 4, appendix D)

    ## first the logical screen width, cannot be 0
    checkbytes = checkfile.read(2)
    logicalscreenwidth = int.from_bytes(checkbytes, byteorder='little')
    if logicalscreenwidth == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid logical screen width'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## then the logical screen height, cannot be 0
    checkbytes = checkfile.read(2)
    logicalscreenheight = int.from_bytes(checkbytes, byteorder='little')
    if logicalscreenheight == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'invalid logical screen height'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## Then extract the packed fields byte (section 18)
    ## the fields describe:
    ##
    ## * global color flag
    ## * color resolution
    ## * sort flag
    ## * size of global color table
    ##
    ## Of these only the ones applying to the global color
    ## table are of interest

    checkbytes = checkfile.read(1)
    unpackedsize += 1

    haveglobalcolortable = False
    if ord(checkbytes) & 0x80 == 0x80:
        haveglobalcolortable = True

    if haveglobalcolortable:
        globalcolortablesize = pow(2, (ord(checkbytes) & 7) + 1) * 3

    ## then skip two bytes
    checkfile.seek(2, os.SEEK_CUR)
    unpackedsize += 2

    ## skip over the global color table, if there is one (section 19)
    if haveglobalcolortable:
        if offset + unpackedsize + globalcolortablesize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for global color table'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(globalcolortablesize, os.SEEK_CUR)
        unpackedsize += globalcolortablesize

    ## then there are 0 or more data blocks
    ## data blocks are either graphic blocks or special purpose blocks
    ## and are followed by a trailer.

    havegiftrailer = False
    animated = False
    allowbrokenxmp = True
    xmpdata = b''
    xmpdom = None

    while True:
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for data blocks or trailer'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

        ## first check to see if there is a trailer (section 27)
        if checkbytes == b'\x3b':
            havegiftrailer = True
            break

        ## The various extensions all start with 0x21 (section 23, 24,
        ## 25, 26, appendix C)
        if checkbytes == b'\x21':
            ## the next byte gives more information about which
            ## extension was used
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for data blocks or trailer'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 1
            ## a graphic block is an optional graphic control extension
            ## (section 23) followed by a graphic rendering block
            if checkbytes == b'\xf9':
                ## then read the next 6 bytes
                checkbytes = checkfile.read(6)
                if len(checkbytes) != 6:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for graphic control extension'}
                    return {'status': False, 'error': unpackingerror}
                if checkbytes[0] != 4:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'wrong value for graphic control extension size'}
                    return {'status': False, 'error': unpackingerror}
                ## last byte is the block terminator (section 16)
                if checkbytes[5] != 0:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'wrong value for graphic control extension block terminator'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 6
            ## process the comment extension (section 24)
            elif checkbytes == b'\xfe':
                ## similar to the image data there is comment data
                ## and then a block terminator
                gifcomment = b''
                while True:
                    checkbytes = checkfile.read(1)
                    if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for block size'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += 1

                    ## check for a block terminator (section 16)
                    if checkbytes == b'\x00':
                        break

                    ## else read the data
                    datasize = ord(checkbytes)
                    if offset + unpackedsize + datasize > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for LZW data bytes'}
                        return {'status': False, 'error': unpackingerror}
                    gifcomment += checkfile.read(datasize)
                    unpackedsize += datasize
            ## process the application extension (section 26)
            elif checkbytes == b'\xff':
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for block size'}
                    return {'status': False, 'error': unpackingerror}
                ## block size describes the application extension header
                ## and has fixed value 11.
                if ord(checkbytes) != 11:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'wrong value for block size'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 1
                if offset + unpackedsize + 11 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for application extension header'}
                    return {'status': False, 'error': unpackingerror}

                ## The structure rest of the rest of the data depends
                ## on the application identifier.

                ## First read the application identifier
                applicationidentifier = checkfile.read(8)

                ## and the application authentication code
                applicationauth = checkfile.read(3)
                unpackedsize += 11

                ## Then process the application data for different
                ## extensions. Only a handful have been defined but
                ## only three are in widespread use (netscape, icc, xmp).
                ##
                ## http://fileformats.archiveteam.org/wiki/GIF#Known_application_extensions
                if applicationidentifier == b'NETSCAPE' and applicationauth == b'2.0':
                    ## http://giflib.sourceforge.net/whatsinagif/bits_and_bytes.html#application_extension_block
                    ## The Netscape extension is for animations.
                    animated = True
                    checkbytes = checkfile.read(4)
                    if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for application data'}
                        return {'status': False, 'error': unpackingerror}
                    if checkbytes[0] != 3 or checkbytes[1] != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'wrong value for application data'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += 4

                    ## finally a block terminator (section 16)
                    checkbytes = checkfile.read(1)
                    if checkbytes != b'\x00':
                        break
                    unpackedsize += 1

                elif applicationidentifier == b'ICCRGBG1' and applicationauth == b'012':
                    ## ICC profiles, http://www.color.org/icc1V42.pdf,
                    ## section B.6
                    iccprofile = b''
                    while True:
                        checkbytes = checkfile.read(1)
                        if len(checkbytes) != 1:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'not enough data for block size'}
                            return {'status': False, 'error': unpackingerror}
                        unpackedsize += 1

                        ## finally a block terminator (section 16)
                        if checkbytes == b'\x00':
                            break

                        ## else read the data
                        datasize = ord(checkbytes)
                        if offset + unpackedsize + datasize > filesize:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'not enough data for ICC data bytes'}
                            return {'status': False, 'error': unpackingerror}
                        iccprofile += checkfile.read(datasize)
                        unpackedsize += datasize
                elif applicationidentifier == b'XMP Data' and applicationauth == b'XMP':
                    ## XMP data
                    ## https://wwwimages2.adobe.com/content/dam/acom/en/devnet/xmp/pdfs/XMP%20SDK%20Release%20cc-2016-08/XMPSpecificationPart3.pdf
                    ## broken XMP headers exist, so store the XMP data
                    ## for a few extra sanity checks.
                    while True:
                        checkbytes = checkfile.read(1)
                        if len(checkbytes) != 1:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'not enough data for block size'}
                            return {'status': False, 'error': unpackingerror}
                        unpackedsize += 1

                        ## finally a block terminator (section 16)
                        if checkbytes == b'\x00' and len(xmpdata) >= 258:
                            break

                        xmpdata += checkbytes

                        ## else read the data
                        datasize = ord(checkbytes)
                        if offset + unpackedsize + datasize > filesize:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'not enough data for ICC data bytes'}
                            return {'status': False, 'error': unpackingerror}
                        xmpdata += checkfile.read(datasize)
                        unpackedsize += datasize
                    xmpdata = xmpdata[:-257]
                    try:
                        xmpdom = xml.dom.minidom.parseString(xmpdata)
                    except:
                        if not allowbrokenxmp:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'invalid XMP data'}
                            return {'status': False, 'error': unpackingerror}

        ## process the image descriptor (section 20)
        elif checkbytes == b'\x2c':
            ## the image descriptor is 10 bytes in total, of which
            ## 1 has already been read
            checkbytes = checkfile.read(9)
            if len(checkbytes) != 9:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for image descriptor'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 9

            ## images can have a separate color table
            havelocalcolortable = False
            if checkbytes[-1] & 0x80 == 0x80:
                havelocalcolortable = True

            ## check if there is a local color table (section 21)
            ## and if so, skip it
            if havelocalcolortable:
                localcolortablesize = pow(2, (ord(checkbytes) & 7) + 1) * 3
                if offset + unpackedsize + localcolortablesize > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for local color table'}
                    return {'status': False, 'error': unpackingerror}
                checkfile.seek(localcolortablesize, os.SEEK_CUR)
                unpackedsize += localcolortablesize

            ## then the image data (section 22)
            ## The first byte describes the LZW minimum code size
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for LZW minimum code size'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 1

            ## then the raster data stream (appendix F).
            while True:
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for block size'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 1

                ## check for a block terminator (section 16)
                if checkbytes == b'\x00':
                    break

                ## else skip over data
                datasize = ord(checkbytes)
                if offset + unpackedsize + datasize > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for LZW data bytes'}
                    return {'status': False, 'error': unpackingerror}
                checkfile.seek(datasize, os.SEEK_CUR)
                unpackedsize += datasize
        else:
            break

    ## if there is no GIF trailer, then the file cannot be valid
    if not havegiftrailer:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False, 'reason': 'GIF trailer not found'}
        return {'status': False, 'error': unpackingerror}

    extrareturn = {}
    if xmpdata != b'' and xmpdom != None:
        extrareturn['xmp'] = xmpdom.toprettyxml()

    if offset == 0 and unpackedsize == filesize:
        ## now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid GIF data according to PIL'}
            return {'status': False, 'error': unpackingerror}
        checkfile.close()

        labels += ['gif', 'graphics']
        if animated:
            labels.append('animated')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels,
                'extra': extrareturn}

    ## Carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked.gif")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    ## reopen the file read only
    outfile = open(outfilename, 'rb')

    ## now load the file into PIL as an extra sanity check
    try:
        testimg = PIL.Image.open(outfile)
        testimg.load()
        testimg.close()
        outfile.close()
    except:
        outfile.close()
        os.unlink(outfilename)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid GIF data according to PIL'}
        return {'status': False, 'error': unpackingerror}

    outlabels = ['gif', 'graphics', 'unpacked']
    if animated:
        outlabels.append('animated')
    unpackedfilesandlabels.append((outfilename, outlabels))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Derived from public ISO9660 specifications
## https://en.wikipedia.org/wiki/ISO_9660
## http://wiki.osdev.org/ISO_9660
## http://www.ecma-international.org/publications/standards/Ecma-119.htm
##
## Throughout the code there will be references to the corresponding
## sections in various specifications.
##
## The Rock Ridge and SUSP specifications:
##
## https://en.wikipedia.org/wiki/Rock_Ridge
##
## IEEE P1282, Draft Version 1.12
## http://www.ymi.com/ymi/sites/default/files/pdf/Rockridge.pdf
## http://web.archive.org/web/20170404043745/http://www.ymi.com/ymi/sites/default/files/pdf/Rockridge.pdf
##
## IEEE P1281 Draft Version 1.12
## http://www.ymi.com/ymi/sites/default/files/pdf/Systems%20Use%20P1281.pdf
## http://web.archive.org/web/20170404132301/http://www.ymi.com/ymi/sites/default/files/pdf/Systems%20Use%20P1281.pdf
##
## The zisofs specific bits can be found at:
## http://libburnia-project.org/wiki/zisofs
def unpackISO9660(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 32769:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 32769 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0

    ## each sector is 2048 bytes long (ECMA 119, 6.1.2). The first 16
    ## sectors are reserved for the "system area" (in total 32768 bytes:
    ## ECMA 119, 6.2.1)
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+32768)
    unpackedsize += 32768

    ## What follows is the data area: ECMA 119, 6.3
    ## This consists of a sequence of volume descriptors
    ## called volume desciptor set (ECMA 119, 6.7.1)
    ## Inside the sequence there should be at least one
    ## primary volume descriptor (ECMA 119, 6.7.1.1) and
    ## at least one terminator (ECMA 119, 6.7.1.6)
    haveprimary = False
    haveterminator = False
    isbootable = False

    ## store whether or not Rock Ridge and zisofs extensions are used
    havesusp = False
    haverockridge = False
    havezisofs = False

    ## read all sectors, until there are none left, or
    ## a volume set descriptor terminator is found
    while True:
        checkbytes = checkfile.read(2048)
        if len(checkbytes) != 2048:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough bytes for sector'}
            return {'status': False, 'error': unpackingerror}

        ## each volume descriptor has a type and an identifier
        ## (ECMA 119, section 8.1)
        if checkbytes[1:6] != b'CD001':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong identifier'}
            return {'status': False, 'error': unpackingerror}

        volumedescriptoroffset = checkfile.tell()

        ## volume descriptor type (ECMA 119, section 8.1.1)
        ## 0: boot record
        ## 1: primary volume descriptor
        ## 2: supplementary volume descriptor or an enhanced volume
        ##    descriptor
        ## 3: volume partition descriptor
        ## 255: volume descriptor set terminator
        if checkbytes[0] == 0:
            ## boot record. There is no additional data here, except
            ## that there could be a bootloader located here, which
            ## could be important for license compliance (isolinux and
            ## friends), so mark this as a bootable CD.
            isbootable = True
        elif checkbytes[0] == 1:
            ## primary volume descriptor (PVD)
            ## ECMA 119, 8.4
            haveprimary = True

            ## most fields are stored in both little endian and big
            ## endian format and should have the same values.
            if int.from_bytes(checkbytes[80:84], byteorder='little') != int.from_bytes(checkbytes[84:88], byteorder='big'):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'endian mismatch'}
                return {'status': False, 'error': unpackingerror}
            ## ECMA 119, 8.4.8
            volume_space_size = int.from_bytes(checkbytes[80:84], byteorder='little')

            ## extra sanity check to see if little endian and big endian
            ## values match.
            if int.from_bytes(checkbytes[128:130], byteorder='little') != int.from_bytes(checkbytes[130:132], byteorder='big'):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'endian mismatch'}
                return {'status': False, 'error': unpackingerror}

            ## ECMA 119, 8.4.12
            logical_size = int.from_bytes(checkbytes[128:130], byteorder='little')

            ## sanity check: the ISO image cannot be outside of the file
            if offset + volume_space_size * logical_size > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'image cannot be outside of file'}
                return {'status': False, 'error': unpackingerror}

            ## according to https://wiki.osdev.org/ISO_9660 Linux does
            ## not use the L-path and M-path but the directory entries
            ## instead.
            ## The PVD contains the directory root entry (ECMA 119, 8.4.8)
            root_directory_entry = checkbytes[156:190]

            ## the entry is formatted as described in ECMA 119, 9.1
            len_dr = root_directory_entry[0]

            ## extent location (ECMA 119, 9.1.3)
            extent_location = int.from_bytes(root_directory_entry[2:6], byteorder='little')
            ## sanity check: the ISO image cannot be outside of the file
            if offset + extent_location * logical_size > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent location cannot be outside file'}
                return {'status': False, 'error': unpackingerror}

            ## sanity check: the ISO image cannot be outside of the
            ## declared size of the file
            if extent_location * logical_size > volume_space_size * logical_size:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent location cannot be larger than declared size'}
                return {'status': False, 'error': unpackingerror}

            ## extent size (ECMA 119, 9.1.4)
            root_directory_extent_length = int.from_bytes(root_directory_entry[10:14], byteorder='little')
            ## sanity check: the ISO image cannot be outside of the file
            if offset + extent_location * logical_size + root_directory_extent_length > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent cannot be outside fle'}
                return {'status': False, 'error': unpackingerror}

            ## sanity check: the ISO image cannot be outside of the
            ## declared size of the file
            if extent_location * logical_size + root_directory_extent_length > volume_space_size * logical_size:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'extent cannot be outside of declared size'}
                return {'status': False, 'error': unpackingerror}

            ## file flags (ECMA 119, 9.1.6)
            if root_directory_entry[25] >> 1 & 1 != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'file flags for directory wrong'}
                return {'status': False, 'error': unpackingerror}

            ## file name length (ECMA 119, 9.1.10)
            file_name_length = root_directory_entry[32]
            extent_filename = root_directory_entry[33:33+file_name_length]

            ## ECMA 119, 7.6: file name for root directory is 0x00
            if extent_filename != b'\x00':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'root file name wrong'}
                return {'status': False, 'error': unpackingerror}

            ## record which extents correspond to which names. This is
            ## important for RockRidge relocations.
            extenttoname = {}
            extenttoparent = {}

            ## recursively walk all entries/extents in the directory
            ## structure.
            ## Keep these in a deque data structure for quick access
            ## For each extent to unpack add:
            ## location of the extent, the size of the extent, location
            ## where to unpack, and the name
            extents = collections.deque()
            extents.append((extent_location, root_directory_extent_length, unpackdir, ''))

            ## keep track of which extents need to be moved.
            extenttomove = {}
            relocatedextents = set()
            plparent = {}

            firstextentprocessed = False

            ## in case rock ridge or zisofs are used the first
            ## directory entry in the first extent will contain
            ## the SP System Use entry, which specifies how many
            ## bytes need to be skipped by default
            ## (IEEE P1281, section 5.3)
            suspskip = 0

            ## then process all the extents with directory records. The
            ## structure is described in ECMA 119, 6.8
            ## In the extent pointed to by a directory entry all the
            ## entries are concatenated (ECMA 119, 6.8.1).
            while len(extents) != 0:
                (this_extent_location, this_extent_length, this_extent_unpackdir, this_extent_name) = extents.popleft()

                ## first seek to the right location in the file
                checkfile.seek(offset + this_extent_location * logical_size)

                ## store the starting offset of the current extent
                orig_extent_offset = checkfile.tell()

                ## a counter of all data that has been read in this
                ## extent so far
                all_extent_offset = 0

                while checkfile.tell() - orig_extent_offset < this_extent_length:
                    ## the entry is formatted as described in ECMA 119, 9.1
                    extent_directory_length = ord(checkfile.read(1))

                    ## then reset the file pointer
                    checkfile.seek(-1,os.SEEK_CUR)

                    ## and store how much data will have been read
                    ## after processing this directory.
                    all_extent_offset += extent_directory_length

                    ## ECMA 119, 6.8.1.1: "each Directory Record shall
                    ## end in the Logical Sector in which it begins"
                    ## This means that there could be padding bytes (NUL)
                    if extent_directory_length == 0:
                        ## if there is still a logical size block then
                        ## jump to the start of that next block
                        all_extent_offset = ((all_extent_offset//logical_size) + 1) * logical_size
                        checkfile.seek(orig_extent_offset + all_extent_offset)
                        continue

                    ## read the directory entry and process according
                    ## to ECMA 119, 9.1
                    directory_entry = bytearray(extent_directory_length)
                    checkfile.readinto(directory_entry)

                    ## extent location (ECMA 119, 9.1.3)
                    extent_location = int.from_bytes(directory_entry[2:6], byteorder='little')
                    ## sanity check: the ISO image cannot be outside
                    ## of the file
                    if offset + extent_location * logical_size > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent location cannot be outside file'}
                        return {'status': False, 'error': unpackingerror}

                    ## sanity check: the ISO image cannot be outside of
                    ## the declared size of the file
                    if extent_location * logical_size > volume_space_size * logical_size:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent location cannot be bigger than declared size'}
                        return {'status': False, 'error': unpackingerror}

                    ## extent size (ECMA 119, 9.1.4)
                    directory_extent_length = int.from_bytes(directory_entry[10:14], byteorder='little')
                    ## sanity check: the ISO image cannot
                    ## be outside of the file
                    if offset + extent_location * logical_size + directory_extent_length > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent cannot be outside file'}
                        return {'status': False, 'error': unpackingerror}

                    ## sanity check: the ISO image cannot be outside of
                    ## the declared size of the file
                    if extent_location * logical_size + directory_extent_length > volume_space_size * logical_size:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'extent outside of declared size'}
                        return {'status': False, 'error': unpackingerror}

                    ## file name length (ECMA 119, 9.1.10)
                    file_name_length = directory_entry[32]

                    ## file name (ECMA 119, 9.1.11)
                    extent_filename = directory_entry[33:33+file_name_length].decode()

                    ## Grab the system use field (ECMA 119, 9.1.13) as
                    ## this is where Rock Ridge and zisofs information
                    ## lives (IEEE P1282, section 3).
                    ## First check if there is a padding byte
                    ## (ECMA 119, 9.1.12)
                    if file_name_length%2 == 0:
                        ## extra check: there should be a padding byte
                        ## if the file name length is even
                        ## (ECMA 119, 9.1.12)
                        if directory_entry[33+file_name_length] != 0:
                            checkfile.close()
                            unpackingerror = {'offset': offset+unpackedsize,
                                              'fatal': False,
                                              'reason': 'no mandatory padding byte found'}
                            return {'status': False, 'error': unpackingerror}
                        system_use = directory_entry[33+file_name_length+1:]
                    else:
                        system_use = directory_entry[33+file_name_length:]

                    ## if RockRidge extensions are used place holder
                    ## files are written when a directory has been
                    ## moved. These files should not be created, so
                    ## indicate whether or not a file needs to be
                    ## created or not.
                    createfile = True

                    if len(system_use) != 0:
                        ## set the offset to the number of bytes that
                        ## should be skipped for each system use area
                        ## according to IEEE P1281, section 5.3
                        suoffset = suspskip

                        ## add a stub for an alternate name as the
                        ## could span multiple entries and need to be
                        ## concatenated.
                        alternatename = b''
                        alternatenamecontinue = True
                        renamecurrentdirectory = False
                        renameparentdirectory = False

                        ## add a stub for a symbolic name as the could
                        ## span multiple entries and need to be
                        ## concatenated.
                        symlinktarget = b''
                        symlinkcontinue = True
                        symlinknamecontinue = True

                        ## store if PL was already seen
                        ## (IEEE P1282, 4.1.5.2)
                        havepl = False

                        ## process according to IEEE P1281, section 4
                        while True:
                            if suoffset >= len(system_use) - 2:
                                break

                            signatureword = system_use[suoffset:suoffset+2]
                            sulength = system_use[suoffset+2]
                            if sulength>len(system_use):
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize,
                                                  'fatal': False,
                                                  'reason': 'invalid length in system use field'}
                                return {'status': False, 'error': unpackingerror}
                            suversion = system_use[suoffset+3]
                            sudata = system_use[suoffset+4:suoffset+4+sulength]

                            ## the 'SP' entry can only appear once per
                            ## directory hierarchy and has to be the
                            ## very first entry of the first directory
                            ## entry of the first extent
                            ## (IEEE P1281, section 5.3)
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
                                if not havesusp:
                                    checkfile.close()
                                    unpackingerror = {'offset': offset+unpackedsize,
                                                      'fatal': False,
                                                      'reason': 'SP not first in System Use area'}
                                    return {'status': False, 'error': unpackingerror}
                                ## depending on the SUSP word that
                                ## follows the contents should be
                                ## interpreted differently
                                if signatureword == b'ST':
                                    ## terminator (IEEE P1281, 5.4)
                                    break
                                elif signatureword == b'RR':
                                    ## this signature word is obsolete
                                    ## but still frequently used to
                                    ## indicate that RockRidge is used
                                    haverockridge = True
                                elif signatureword == b'CE':
                                    ## the continuation area
                                    continuation_block = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                    continuation_offset = int.from_bytes(system_use[suoffset+12:suoffset+16], byteorder='little')
                                    continuation_length = int.from_bytes(system_use[suoffset+20:suoffset+24], byteorder='little')

                                    ## first check whether or not the
                                    ## continuation data is inside the
                                    ## ISO image.
                                    if volume_space_size * logical_size < continuation_block * logical_size + continuation_offset + continuation_length:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'invalid continuation area location or size'}
                                        return {'status': False, 'error': unpackingerror}

                                    ## store the current position in the file
                                    oldoffset = checkfile.tell()
                                    checkfile.seek(continuation_block * logical_size + continuation_offset)
                                    ## continuation_bytes = checkfile.read(continuation_length)
                                    ## TODO

                                    ## return to the original position
                                    ## in the file
                                    checkfile.seek(oldoffset)
                                elif signatureword == b'NM' and alternatenamecontinue:
                                    ## The alternate name field is
                                    ## described in IEEE P1282, 4.1.4
                                    nmflags = system_use[suoffset+4]

                                    ## sanity check: only one of the
                                    ## lower bits can be set
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
                                    ## no need to process padding areas
                                    pass
                                elif signatureword == b'PN':
                                    ## no need to process POSIX device numbers
                                    pass
                                elif signatureword == b'PX':
                                    ## This entry is mandatory, so a
                                    ## good indicator that RockRidge is
                                    ## used in case there is no RR entry.
                                    haverockridge = True
                                    ## don't process POSIX flags
                                    pass
                                elif signatureword == b'SL' and symlinkcontinue:
                                    ## symbolic links, IEEE P1282, 4.1.3
                                    symflags = system_use[suoffset+4]

                                    ## sanity check: only one of the
                                    ## lower bits can be set
                                    nmflagtotal = (symflags & 1) + (symflags >> 1 & 1) + (symflags >> 2 & 1)
                                    if nmflagtotal > 1:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'invalid flag combination in alternate name field'}
                                        return {'status': False, 'error': unpackingerror}

                                    if sulength - 5 != 0:
                                        ## the rest of the data is the
                                        ## component area the first byte
                                        ## is a bit field
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
                                            ## the next byte is the length
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
                                    ## no need to process sparse file as
                                    ## it doesn't seem to be supported
                                    ## well in the real world
                                    pass
                                elif signatureword == b'TF':
                                    ## don't process time field
                                    pass

                                ## the following three signature words
                                ## are involved in directory relocations
                                elif signatureword == b'CL':
                                    ## IEEE P1282, 4.1.5.1 says:
                                    ## If an entry is tagged with CL it
                                    ## means that this entry is a
                                    ## placeholder file with the same
                                    ## name as the directory and that the
                                    ## directory should be moved to
                                    ## this location.
                                    location_child = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                    if volume_space_size < location_child:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'invalid directory relocation'}
                                        return {'status': False, 'error': unpackingerror}

                                    ## don't create, simply store
                                    createfile = False

                                    ## store the directory here
                                    extenttomove[location_child] = this_extent_location
                                elif signatureword == b'PL':
                                    ## IEEE P1282, 4.1.5.2: PL entry is
                                    ## recorded in SUSP field for the
                                    ## parent field.
                                    ## This value points to the original
                                    ## parent of the file.
                                    if extent_filename != '\x01':
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'PL in wrong directory entry'}
                                        return {'status': False, 'error': unpackingerror}

                                    ## IEEE P1282, 4.1.5.2: only one
                                    ## PL entry is allowed per directory
                                    ## entry.
                                    if havepl:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'duplicate PL entry'}
                                        return {'status': False, 'error': unpackingerror}
                                    havepl = True

                                    ## location cannot be outside of file
                                    location_parent = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                    if volume_space_size < location_parent:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'relocated directory parent outside of file'}
                                        return {'status': False, 'error': unpackingerror}

                                    ## record the original parent for
                                    ## this extent
                                    plparent[this_extent_location] = location_parent
                                elif signatureword == b'RE':
                                    ## IEEE P1282, 4.1.5.3 describes
                                    ## that the directory entry that is
                                    ## described is labeled as
                                    ## relocated, so record it as such.
                                    relocatedextents.add(extent_location)

                                ## zisofs extension
                                elif signatureword == b'ZF':
                                    havezisofs = True
                                    ## some sanity checks
                                    pz = system_use[suoffset+4:suoffset+6]
                                    if pz != b'pz':
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'unsupported zisofs compression'}
                                        return {'status': False, 'error': unpackingerror}
                                    zisofs_header_div_4 = system_use[suoffset+6]

                                    ## Log2 of Block Size
                                    ## must be 15, 16 or 17
                                    zisofs_header_log = system_use[suoffset+7]
                                    if zisofs_header_log not in [15,16,17]:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize,
                                                          'fatal': False,
                                                          'reason': 'unsupported zisofs block size log'}
                                        return {'status': False, 'error': unpackingerror}
                                    zisofs_uncompressed = int.from_bytes(system_use[suoffset+8:suoffset+12], byteorder='little')
                            ## skip all the other signature words
                            suoffset += sulength

                    ## file flags (ECMA 119, 9.1.6)

                    if directory_entry[25] >> 1 & 1 == 1:
                        ## directory entry
                        if extent_filename == '\x00':
                            ## Look at the file name. If it is '.. then
                            ## it is safe to skip, but do a sanity check
                            ## to see if the location matches with the
                            ## current one.
                            if not this_extent_location == extent_location:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize,
                                                  'fatal': False,
                                                  'reason': 'wrong back reference for . directory'}
                                return {'status': False, 'error': unpackingerror}
                        elif extent_filename == '\x01':
                            ## TODO: extra sanity checks to see if parent matches
                            pass
                        else:
                            ## store the name of the parent,
                            ## for extra sanity checks
                            extenttoparent[extent_location] = this_extent_location

                            extent_unpackdir = os.path.join(this_extent_unpackdir, extent_filename)
                            if haverockridge:
                                if not renamecurrentdirectory or renameoarentdirectory:
                                    if alternatename != b'':
                                        try:
                                            alternatename = alternatename.decode()
                                            extent_unpackdir = os.path.join(this_extent_unpackdir, alternatename)
                                        except:
                                            pass
                            extenttoname[extent_location] = extent_unpackdir
                            os.mkdir(extent_unpackdir)
                            extents.append((extent_location, directory_extent_length, extent_unpackdir, ''))
                    else:
                        ## file entry
                        ## store the name of the parent,
                        ## for extra sanity checks
                        extenttoparent[extent_location] = this_extent_location
                        outfilename = os.path.join(this_extent_unpackdir, extent_filename.rsplit(';', 1)[0])
                        if haverockridge:
                            if alternatename != b'':
                                if not renamecurrentdirectory or renameoarentdirectory:
                                    try:
                                        alternatename = alternatename.decode()
                                        outfilename = os.path.join(this_extent_unpackdir, alternatename)
                                    except:
                                        pass

                        if len(symlinktarget) != 0:
                            try:
                                symlinktarget = symlinktarget.decode()
                            except:
                                pass

                            ## absolute symlinks can always be created,
                            ## as can links to . and ..
                            if os.path.isabs(symlinktarget):
                                os.symlink(symlinktarget, outfilename)
                            elif symlinktarget == '.' or symlinktarget == '..':
                                os.symlink(symlinktarget, outfilename)
                            else:
                                ## first chdir to the directory, then
                                ## create the link and go back
                                olddir = os.getcwd()
                                os.chdir(os.path.dirname(outfilename))
                                os.symlink(symlinktarget, outfilename)
                                os.chdir(olddir)
                            unpackedfilesandlabels.append((outfilename, ['symbolic link']))
                            createfile = False

                        if createfile:
                            outfile = open(outfilename, 'wb')
                            if not havezisofs:
                                os.sendfile(outfile.fileno(), checkfile.fileno(), offset + extent_location * logical_size, directory_extent_length)
                            else:
                                ## first some sanity checks
                                zisofs_oldoffset = checkfile.tell()
                                checkfile.seek(offset + extent_location * logical_size)
                                if filesize - checkfile.tell() < 16:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'not enough bytes for zisofs header'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                ## first 8 bytes are the zisofs magic
                                checkbytes = checkfile.read(8)
                                if checkbytes != b'\x37\xe4\x53\x96\xc9\xdB\xd6\x07':
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'wrong magic for zisofs data'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                ## then the uncompressed size. Should be
                                ## the same as in the SUSP entry
                                checkbytes = checkfile.read(4)
                                if int.from_bytes(checkbytes, byteorder='little') != zisofs_uncompressed:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'mismatch for uncompressed size in zisofs header and SUSP'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                ## then the zisofs header size
                                checkbytes = checkfile.read(1)
                                if not ord(checkbytes) == zisofs_header_div_4:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'mismatch between zisofs header and SUSP'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                ## then the zisofs log2(block size)
                                checkbytes = checkfile.read(1)
                                if not ord(checkbytes) == zisofs_header_log:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'mismatch between zisofs header and SUSP'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                block_size = pow(2,zisofs_header_log)

                                ## then two reserved bytes
                                checkbytes = checkfile.read(2)
                                if not int.from_bytes(checkbytes, byteorder='little') == 0:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'wrong value for reserved bytes'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                ## then the pointer array
                                blockpointers = math.ceil(zisofs_uncompressed/block_size)+1
                                blockpointerarray = []
                                for b in range(0,blockpointers):
                                    checkbytes = checkfile.read(4)
                                    if not len(checkbytes) == 4:
                                        unpackingerror = {'offset': checkfile.tell() - offset,
                                                          'fatal': False,
                                                          'reason': 'not enough data for block pointer'}
                                        checkfile.close()
                                        return {'status': False, 'error': unpackingerror}
                                    blockpointer = int.from_bytes(checkbytes, byteorder='little')
                                    if blockpointer > directory_extent_length:
                                        unpackingerror = {'offset': checkfile.tell() - offset,
                                                          'fatal': False,
                                                          'reason': 'block pointer cannot be outside extent'}
                                        checkfile.close()
                                        return {'status': False, 'error': unpackingerror}
                                    blockpointerarray.append(blockpointer)

                                totalwritten = 0
                                for b in range(0, len(blockpointerarray) -1):
                                    blockpointer = blockpointerarray[b]
                                    nextblockpointer = blockpointerarray[b+1]
                                    ## in case the two pointers are the
                                    ## same a block of NULs should be
                                    ## written. Normally this is blocksize
                                    ## bytes unless there are fewer bytes
                                    ## to be left to write. The
                                    ## specification does not mention this.
                                    if blockpointer == nextblockpointer:
                                        if zisofs_uncompressed - totalwritten > block_size:
                                            outfile.seek(block_size, os.SEEK_CUR)
                                            totalwritten += block_size
                                        else:
                                            outfile.seek(zisofs_uncompressed - totalwritten, os.SEEK_CUR)
                                            totalwritten += (zisofs_uncompressed - totalwritten)
                                    else:
                                            totalwritten += outfile.write(zlib.decompress(checkfile.read(nextblockpointer-blockpointer)))

                                ## extra sanity check, unsure if this is correct, but seems so
                                if blockpointerarray[-1] < directory_extent_length:
                                    unpackingerror = {'offset': checkfile.tell() - offset,
                                                      'fatal': False,
                                                      'reason': 'block pointer ends before directory extent'}
                                    checkfile.close()
                                    return {'status': False, 'error': unpackingerror}

                                checkfile.seek(zisofs_oldoffset)
                            outfile.close()
                            unpackedfilesandlabels.append((outfilename, []))

                    ## then skip to the (possible) start of
                    ## the next directory entry.
                    checkfile.seek(orig_extent_offset + all_extent_offset)

                firstextentprocessed = True

            for e in extenttomove:
                ## First check if all the PL and CL references are
                ## correct, before moving extent e to extenttomove[e]
                ## 1. extentmove[e] should be the parent
                ##    e will be moved to.
                targetparent = extenttomove[e]

                ## 2. see if the targetparent is the same
                ##    as the recorded value in plparent[e]
                if not targetparent == plparent[e]:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'CL/PL entries do not match'}
                    return {'status': False, 'error': unpackingerror}

                ## now move the directory and all its contents
                ## to the right location
                shutil.move(extenttoname[e], extenttoname[extenttomove[e]])

                ## fix references for unpacked files if necessary
                newunpackedfilesandlabels = []
                for u in unpackedfilesandlabels:
                    if u[0].startswith(extenttoname[e]):
                        newunpackedfilesandlabels.append((u[0].replace(os.path.dirname(extenttoname[e]), extenttoname[extenttomove[e]], 1), u[1]))
                    else:
                        newunpackedfilesandlabels.append(u)
                unpackedfilesandlabels = newunpackedfilesandlabels

                ## fix references for extent names
                for n in extenttoname:
                    if n != e:
                        if extenttoname[n].startswith(extenttoname[e]):
                            extenttoname[n] = extenttoname[n].replace(os.path.dirname(extenttoname[e]), extenttoname[extenttomove[e]], 1)

                ## finally rewrite the name of the extent moved itself
                extenttoname[e] = extenttoname[e].replace(os.path.dirname(extenttoname[e]), extenttoname[extenttomove[e]], 1)

            ## finally return to the old offset to read more
            ## volume descriptors
            checkfile.seek(volumedescriptoroffset)
        elif checkbytes[0] == 2:
            ## supplementary or enhanced volume descriptor
            ## used for for example Joliet (ECMA 119, appendix B.2)
            pass
        elif checkbytes[0] == 3:
            pass
        elif checkbytes[0] == 255:
            ## ECMA 119, 8.3.1
            haveterminator = True
            if not haveprimary:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no primary volume descriptor'}
                return {'status': False, 'error': unpackingerror}
        elif checkbytes[0] > 3 and checkbytes[0] < 255:
            ## reserved blocks, for future use, have never been
            ## implemented for ISO9660.
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'no primary volume descriptor'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2048

        if haveterminator:
            break

    checkfile.close()

    ## there should always be at least one terminator. If not,
    ## then it is not a valid ISO file
    if not haveterminator:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no volume terminator descriptor'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = volume_space_size * logical_size

    if offset == 0 and unpackedsize == filesize:
        labels += ['iso9660', 'file system']
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## http://www.nongnu.org/lzip/manual/lzip_manual.html#File-format
def unpackLzip(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    if filesize < 26:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then the version number, should be 1
    lzipversion = ord(checkfile.read(1))
    if lzipversion != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported lzip version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## then the LZMA dictionary size. The lowest 5 bits are
    ## the dictionary base size.
    checkbytes = checkfile.read(1)
    dictionarybasesize = pow(2, ord(checkbytes) & 31)
    dictionarysize = dictionarybasesize - (int(dictionarybasesize/16)) * (ord(checkbytes) >> 5)
    unpackedsize += 1

    ## create a LZMA decompressor with custom filter, as the data is
    ## stored without LZMA headers. The LZMA properties are hardcoded
    ## for lzip, except the dictionary.
    lzma_lc = 3
    lzma_lp = 0
    lzma_pb = 2

    lzip_filters = [
         {"id": lzma.FILTER_LZMA1, "dict_size": dictionarybasesize, 'lc': lzma_lc, 'lp': lzma_lp, 'pb': lzma_pb},
    ]

    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=lzip_filters)
    if not filename.suffix.lower() == '.lz':
        outfilename = os.path.join(unpackdir, "unpacked-from-lzip")
    else:
        outfilename = os.path.join(unpackdir, filename.stem)
    outfile = open(outfilename, 'wb')

    ## while decompressing also compute the CRC of the uncompressed
    ## data, as it is stored after the compressed LZMA data in the file
    crccomputed = binascii.crc32(b'')

    readsize = 1000000
    checkdata = bytearray(readsize)
    checkfile.readinto(checkdata)

    while checkdata != b'':
        try:
            unpackeddata = decompressor.decompress(checkdata)
        except EOFError as e:
            break
        except Exception as e:
            ## clean up
            outfile.close()
            os.unlink(outfilename)
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not valid LZMA data'}
            return {'status': False, 'error': unpackingerror}
        outfile.write(unpackeddata)
        crccomputed = binascii.crc32(unpackeddata, crccomputed)
        ## there is no more compressed data
        unpackedsize += len(checkdata) - len(decompressor.unused_data)
        if decompressor.unused_data != b'':
            break
        checkfile.readinto(checkdata)

    outfile.close()

    ## first reset to the end of the LZMA compressed data
    checkfile.seek(offset+unpackedsize)

    ## then four bytes of CRC32
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for CRC'}
        return {'status': False, 'error': unpackingerror}

    crcstored = int.from_bytes(checkbytes, byteorder='little')
    ## the CRC stored is the CRC of the uncompressed data
    if crcstored != crccomputed:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong CRC'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## then the size of the original uncompressed data
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for original data size'}
        return {'status': False, 'error': unpackingerror}
    originalsize = int.from_bytes(checkbytes, byteorder='little')
    if originalsize != os.stat(outfilename).st_size:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong original data size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    ## then the member size
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for member size'}
        return {'status': False, 'error': unpackingerror}
    membersize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## the member size has to be the same as the unpacked size
    if membersize != unpackedsize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong member size'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    unpackedfilesandlabels.append((outfilename, []))
    if offset == 0 and unpackedsize == filesize:
        labels.append('compressed')
        labels.append('lzip')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## JPEG
## https://www.w3.org/Graphics/JPEG/
##
## ITU T.81 https://www.w3.org/Graphics/JPEG/itu-t81.pdf
## appendix B describes the format in great detail, especially
## figure B.16
##
## https://en.wikipedia.org/wiki/JPEG#Syntax_and_structure
## also has an extensive list of the markers
def unpackJPEG(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## open the file and skip the SOI magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+2)
    unpackedsize += 2

    ## then further process the frame according to B.2.1
    ## After SOI there are optional tables/miscellaneous (B.2.4)
    ## These are defined in B.2.4.*. Marker values are in B.1
    ## JPEG is in big endian order (B.1.1.1)

    ## DQT, DHT, DAC, DRI, COM
    tablesmiscmarkers = set([b'\xff\xdb', b'\xff\xc4', b'\xff\xcc',
                             b'\xff\xdd', b'\xff\xfe'])

    ## RST0-7
    rstmarkers = set([b'\xff\xd0', b'\xff\xd1', b'\xff\xd2', b'\xff\xd3',
                     b'\xff\xd4', b'\xff\xd5', b'\xff\xd6', b'\xff\xd7'])

    ## JPEG extension markers -- are these actually being used by someone?
    jpegextmarkers = set([b'\xff\xc8', b'\xff\xf0', b'\xff\xf1', b'\xff\xf2',
                          b'\xff\xf3', b'\xff\xf4', b'\xff\xf5', b'\xff\xf6',
                          b'\xff\xf7', b'\xff\xf8', b'\xff\xf9', b'\xff\xfa',
                          b'\xff\xfb', b'\xff\xfc', b'\xff\xfd'])

    ## APP0-n (16 values)
    appmarkers = set([b'\xff\xe0', b'\xff\xe1', b'\xff\xe2', b'\xff\xe3',
                      b'\xff\xe4', b'\xff\xe5', b'\xff\xe6', b'\xff\xe7',
                      b'\xff\xe8', b'\xff\xe9', b'\xff\xea', b'\xff\xeb',
                      b'\xff\xec', b'\xff\xed', b'\xff\xee', b'\xff\xef'])

    ## start of frame markers
    startofframemarkers = set([b'\xff\xc0', b'\xff\xc1', b'\xff\xc2',
                               b'\xff\xc3', b'\xff\xc5', b'\xff\xc6',
                               b'\xff\xc7', b'\xff\xc9', b'\xff\xca',
                               b'\xff\xcb', b'\xff\xcd', b'\xff\xce',
                               b'\xff\xcf'])

    ## keep track of whether or not a frame can be restarted
    restart = False
    eofseen = False

    seenmarkers = set()
    while True:
        checkbytes = checkfile.read(2)
        if not len(checkbytes) == 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for table/misc'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        if checkbytes in tablesmiscmarkers or checkbytes in appmarkers:
            marker = checkbytes
            seenmarkers.add(checkbytes)
            ## extract the length of the table or app marker.
            ## this includes the 2 bytes of the length field itself
            checkbytes = checkfile.read(2)
            if not len(checkbytes) == 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table/misc length field'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            misctablelength = int.from_bytes(checkbytes, byteorder='big')
            if checkfile.tell() + misctablelength - 2 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'table outside of file'}
                return {'status': False, 'error': unpackingerror}

            if marker == b'\xff\xdd':
                ## DRI
                oldoffset = checkfile.tell()
                checkbytes = checkfile.read(2)
                restartinterval = int.from_bytes(checkbytes, byteorder='big')
                if restartinterval != 0:
                    restart = True
                checkfile.seek(oldoffset)
            elif marker == b'\xff\xdb':
                ## DQT, not present for lossless JPEG by definition (B.2.4.1)
                oldoffset = checkfile.tell()
                ## check Pq and Tq
                checkbytes = checkfile.read(1)
                pqtq = ord(checkbytes)
                pq = pqtq >> 4
                if not (pq == 0 or pq == 1):
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid DQT value'}
                    return {'status': False, 'error': unpackingerror}
                tq = pqtq & 15
                if not tq < 4:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid DQT value'}
                    return {'status': False, 'error': unpackingerror}
                checkfile.seek(oldoffset)
            elif marker == b'\xff\xe0':
                ## APP0, TODO
                oldoffset = checkfile.tell()
                checkbytes = checkfile.read(5)
                checkfile.seek(oldoffset)
            elif marker == b'\xff\xe1':
                ## APP1, EXIF and friends
                ## EXIF could have a thumbnail, TODO
                oldoffset = checkfile.tell()
                checkbytes = checkfile.read(5)
                checkfile.seek(oldoffset)

            ## skip over the section
            checkfile.seek(misctablelength-2, os.SEEK_CUR)
            unpackedsize += misctablelength-2
        else:
            break

    ## the abbreviated syntax is not widely used, so do not allow it
    allowabbreviated = False

    if allowabbreviated:
        ## There *could* be an EOI marker here and it would be
        ## a valid JPEG according to section B.5, although not
        ## all markers would be allowed.
        if checkbytes == b'\xff\xd9':
            if len(seenmarkers) == 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no tables present, needed for abbreviated syntax'}
                return {'status': False, 'error': unpackingerror}
            ## according to B.5 DAC and DRI are not allowed in this syntax.
            if b'\xff\xcc' in seenmarkers or b'\xff\xdd' in seenmarkers:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'DAC and/or DRI not allowed in abbreviated syntax'}
                return {'status': False, 'error': unpackingerror}
            if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels.append('graphics')
                labels.append('jpeg')
                return {'status': True, 'length': unpackedsize, 'labels': labels,
                        'filesandlabels': unpackedfilesandlabels}

            ## else carve the file
            outfilename = os.path.join(unpackdir, "unpacked.jpg")
            outfile = open(outfilename, 'wb')
            os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
            outfile.close()
            unpackedfilesandlabels.append((outfilename, ['graphics', 'jpeg', 'unpacked']))
            checkfile.close()
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    ishierarchical = False

    ## there could be a DHP segment here according to section B.3,
    ## but only one in the entire image
    if checkbytes == b'\xff\xde':
        checkbytes = checkfile.read(2)
        if not len(checkbytes) == 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for table/misc length field'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2
        sectionlength = int.from_bytes(checkbytes, byteorder='big')
        if checkfile.tell() + sectionlength - 2 > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'table outside of file'}
            return {'status': False, 'error': unpackingerror}

        ishierarchical = True

        ## skip over the section
        checkfile.seek(sectionlength-2, os.SEEK_CUR)
        unpackedsize += sectionlength-2

        ## and make sure that there are already a few bytes read
        checkbytes = checkfile.read(2)
        if not len(checkbytes) == 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for table/misc'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

    ## now there could be multiple frames, starting with optional
    ## misc/tables again.
    while True:
        framerestart = restart
        while True:
            if checkbytes in tablesmiscmarkers or checkbytes in appmarkers:
                isdri = False
                if checkbytes == b'\xff\xdd':
                    isdri = True
                ## extract the length of the table or app marker.
                ## this includes the 2 bytes of the length field itself
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc length field'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2
                misctablelength = int.from_bytes(checkbytes, byteorder='big')
                if checkfile.tell() + misctablelength - 2 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'table outside of file'}
                    return {'status': False, 'error': unpackingerror}

                if isdri:
                    oldoffset = checkfile.tell()
                    checkbytes = checkfile.read(2)
                    restartinterval = int.from_bytes(checkbytes, byteorder='big')
                    if restartinterval != 0:
                        framerestart = True
                    checkfile.seek(oldoffset)

                ## skip over the section
                checkfile.seek(misctablelength-2, os.SEEK_CUR)
                unpackedsize += misctablelength-2
                checkbytes = checkfile.read(2)

                ## and read the next few bytes
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2
            else:
                break

        ## check if this is EXP (only in hierarchical syntax)
        if checkbytes == b'\xff\xdf':
            if not ishierarchical:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'EXP only allowed in hierarchical syntax'}
                return {'status': False, 'error': unpackingerror}
            checkbytes = checkfile.read(2)
            if not len(checkbytes) == 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table/misc length field'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            misctablelength = int.from_bytes(checkbytes, byteorder='big')
            if checkfile.tell() + misctablelength - 2 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'table outside of file'}
                return {'status': False, 'error': unpackingerror}

            ## skip over the section
            checkfile.seek(misctablelength-2, os.SEEK_CUR)
            unpackedsize += misctablelength-2

            ## and read the next two bytes
            checkbytes = checkfile.read(2)
            if not len(checkbytes) == 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table/misc'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

        ## after the tables/misc and possibly EXP there should be
        ## a frame header (B.2.2) with a SOF (start of frame) marker
        if checkbytes in startofframemarkers:
            ## extract the length of the frame
            ## this includes the 2 bytes of the length field itself
            checkbytes = checkfile.read(2)
            if not len(checkbytes) == 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table/misc length field'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            misctablelength = int.from_bytes(checkbytes, byteorder='big')
            if checkfile.tell() + misctablelength - 2 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'table outside of file'}
                return {'status': False, 'error': unpackingerror}
            ## skip over the section
            checkfile.seek(misctablelength-2, os.SEEK_CUR)
            unpackedsize += misctablelength-2
        else:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid value for start of frame'}
            return {'status': False, 'error': unpackingerror}

        ## This is followed by at least one scan header,
        ## optionally preceded by more tables/misc
        while True:
            if eofseen:
                break
            ## optionally preceded by more tables/misc
            while True:
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2

                if checkbytes in tablesmiscmarkers or checkbytes in appmarkers:
                    ## Extract the length of the table or app marker.
                    ## This includes the 2 bytes of the length field itself
                    checkbytes = checkfile.read(2)
                    if not len(checkbytes) == 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'not enough data for table/misc length field'}
                        return {'status': False, 'error': unpackingerror}
                    unpackedsize += 2
                    misctablelength = int.from_bytes(checkbytes, byteorder='big')
                    if checkfile.tell() + misctablelength - 2 > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'table outside of file'}
                        return {'status': False, 'error': unpackingerror}

                    ## skip over the section
                    checkfile.seek(misctablelength-2, os.SEEK_CUR)
                    unpackedsize += misctablelength-2
                else:
                    break

            ## RST: no data, so simply ignore, but immediately
            ## skip to more of the raw data.
            isrestart = False
            if checkbytes in rstmarkers:
                isrestart = True

            ## DNL (section B.2.5)
            if checkbytes == b'\xff\xdc':
                ## extract the length of the DNL
                ## this includes the 2 bytes of the length field itself
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc length field'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2

                headerlength = int.from_bytes(checkbytes, byteorder='big')
                if checkfile.tell() + headerlength - 2 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'start of scan outside of file'}
                    return {'status': False, 'error': unpackingerror}
                ## skip over the section
                checkfile.seek(headerlength-3, os.SEEK_CUR)
                unpackedsize += headerlength - 3

                ## and read two bytes
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2

            ## the SOS (start of scan) header
            if checkbytes == b'\xff\xda':
                ## extract the length of the start of scan header
                ## this includes the 2 bytes of the length field itself
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc length field'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2

                headerlength = int.from_bytes(checkbytes, byteorder='big')
                if checkfile.tell() + headerlength - 2 > filesize:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'start of scan outside of file'}
                    return {'status': False, 'error': unpackingerror}

                ## the number of image components, can only be 1-4
                checkbytes = checkfile.read(1)
                numberimagecomponents = ord(checkbytes)
                if numberimagecomponents not in [1,2,3,4]:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid value for number of image components'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 1

                ## the header length = 6+2* number of image components
                if headerlength != 6+2*numberimagecomponents:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid value for number of image components or start of scan header length'}
                    return {'status': False, 'error': unpackingerror}

                ## skip over the section
                checkfile.seek(headerlength-3, os.SEEK_CUR)
                unpackedsize += headerlength - 3
            else:
                if not isrestart:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid value for start of scan'}
                    return {'status': False, 'error': unpackingerror}

            ## now read the image data in chunks to search for
            ## JPEG markers (section B.1.1.2)
            ## This is not fully fool proof: if data from the
            ## entropy coded segment (ECS) is missing, or if data
            ## has been inserted or changed in the ECS. The only
            ## way to verify this is to reimplement it, or to run
            ## it through an external tool or library such as pillow.
            readsize = 100
            while True:
                oldpos = checkfile.tell()
                checkbytes = checkfile.read(readsize)
                if checkbytes == b'':
                    break
                ## check if 0xff can be found in the data. If so, then it
                ## is either part of the entropy coded data (and followed
                ## by 0x00), or a valid JPEG marker, or bogus data.
                if b'\xff' in checkbytes:
                    startffpos = 0
                    fffound = False
                    while True:
                        ffpos = checkbytes.find(b'\xff', startffpos)
                        if ffpos == -1:
                            break
                        startffpos = ffpos + 1
                        if ffpos < readsize - 1:
                            if checkbytes[ffpos+1] != 0:
                                if checkbytes[ffpos:ffpos+2] in tablesmiscmarkers or checkbytes[ffpos:ffpos+2] in appmarkers:
                                    checkfile.seek(oldpos + ffpos)
                                    fffound = True
                                    break
                                if checkbytes[ffpos:ffpos+2] in jpegextmarkers:
                                    checkfile.seek(oldpos + ffpos)
                                    fffound = True
                                    break
                                if checkbytes[ffpos:ffpos+2] in rstmarkers:
                                    checkfile.seek(oldpos + ffpos)
                                    fffound = True
                                    break
                                ## check for SOS
                                if checkbytes[ffpos:ffpos+2] == b'\xff\xda':
                                    checkfile.seek(oldpos + ffpos)
                                    fffound = True
                                    break
                                ## check for DNL
                                if checkbytes[ffpos:ffpos+2] == b'\xff\xdc':
                                    checkfile.seek(oldpos + ffpos)
                                    fffound = True
                                    break
                                ## check for EOI
                                if checkbytes[ffpos:ffpos+2] == b'\xff\xd9':
                                    checkfile.seek(oldpos + ffpos + 2)
                                    eofseen = True
                                    fffound = True
                                    break

                    ## set unpacked size to whatever data was read
                    unpackedsize = checkfile.tell() - offset

                    ## a valid marker was found, so break out of the loop
                    if fffound:
                        break
                else:
                    unpackedsize = checkfile.tell() - offset
                if checkfile.tell() == filesize:
                    break
                checkfile.seek(-1, os.SEEK_CUR)

        ## end of the image, so break out of the loop
        if eofseen:
            break

    if offset == 0 and unpackedsize == filesize:
        ## now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid JPEG data according to PIL'}
            return {'status': False, 'error': unpackingerror}
        checkfile.close()

        labels.append('graphics')
        labels.append('jpeg')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    outfilename = os.path.join(unpackdir, "unpacked.jpg")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    ## open as read only
    outfile = open(outfilename, 'rb')

    ## now load the file into PIL as an extra sanity check
    try:
        testimg = PIL.Image.open(outfile)
        testimg.load()
        testimg.close()
        outfile.close()
    except:
        outfile.close()
        os.unlink(outfilename)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid JPEG data according to PIL'}
        return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfilename, ['jpeg', 'graphics', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Derived from specifications at:
## https://www.w3.org/TR/WOFF/
## section 3 and 4 describe the format
def unpackWOFF(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    checkfile = open(filename, 'rb')

    ## skip over the header
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## next 4 bytes are the "flavour" of the font. Don't use for now.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for font flavour'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## next 4 bytes are the size of the font.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for font size'}
        return {'status': False, 'error': unpackingerror}

    ## the font cannot be outside of the file
    fontsize = int.from_bytes(checkbytes, byteorder='big')
    if offset + fontsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'declared font size outside file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## next the number of tables
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for number of tables'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    numtables = int.from_bytes(checkbytes, byteorder='big')

    ## next a reserved field. Should be set to 0
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

    ## next the totalSfntSize. This field must be divisible by 4.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for totalSfntSize'}
        return {'status': False, 'error': unpackingerror}
    if int.from_bytes(checkbytes, byteorder='big')%4 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not aligned on 4 byte boundary'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## then the major version
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for major version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## and the minor version
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for minor version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## the location of the meta data block. This offset cannot be
    ## outside the file.
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
    ## the private data block MUST start on a 4 byte boundary (section 7)
    if metaoffset % 4 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'meta data doesn\'t start on 4 byte boundary'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## the length of the compressed meta data block. This cannot be
    ## outside the file.
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

    ## then the original length of the meta data. Ignore for now.
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for original meta data length'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## the location of the private data block. This offset cannot be
    ## outside the file.
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
    ## the private data block MUST start on a 4 byte boundary (section 8)
    if privateoffset % 4 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'private data block doesn\'t start on 4 byte boundary'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## the length of the private data block.
    ## This cannot be outside the file.
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

    ## then the "table directory"
    lastseenoffset = 0
    for t in range(0,numtables):
        ## the tag of the table
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for tag table'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## the offset of the table. This cannot be outside of the file.
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

        ## then the length of the compressed data, excluding padding
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

        ## then the length of the uncompressed data, excluding padding.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for uncompressed table length'}
            return {'status': False, 'error': unpackingerror}
        tableuncompressedlength = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        ## then the checksum of the uncompressed data.
        ## Can be ignored for now
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for uncompressed data checksum'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## If the compressed length is the same as uncompressed,
        ## then the data is stored uncompressed. Since this has
        ## already been verified in an earlier check there is no
        ## need to further check (section 5 of specifications).

        if tablecompressedlength < tableuncompressedlength:
            ## Then jump to the right place in the file (tableoffset)
            ## and read the bytes.
            ## first store the old offset
            prevoffset = checkfile.tell()
            checkfile.seek(offset+tableoffset)
            checkbytes = checkfile.read(tablecompressedlength)

            ## then try to decompress the bytes read with zlib
            zlibdecompressor = zlib.decompressobj()
            uncompresseddata = zlibdecompressor.decompress(checkbytes)
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

            ## then return to the previous offset
            checkfile.seek(prevoffset)

        ## store the last valid offset seen. Fonts don't need to
        ## appear in order in the font table.
        lastseenoffset = max(lastseenoffset, offset + tableoffset + tablecompressedlength)

    ## set the unpackedsize to the maximum of the last seen offset and
    ## the unpacked size. This is done in case the font table is empty.
    unpackedsize = max(lastseenoffset, unpackedsize) - offset

    ## the declared fontsize cannot be smaller than what was unpacked
    if unpackedsize > fontsize:
        checkfile.close()
        unpackingerror = {'offset': offset+tableoffset, 'fatal': False,
                          'reason': 'size of unpacked data larger than declared font size'}
        return {'status': False, 'error': unpackingerror}

    ## it could be that there is padding. There should be a maximum
    ## of three bytes for padding.
    if fontsize - unpackedsize > 3:
        checkfile.close()
        unpackingerror = {'offset': offset+tableoffset, 'fatal': False,
                          'reason': 'declared font size too large for unpacked data'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = fontsize

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels += ['woff', 'font', 'resource']
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked-woff")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['woff', 'font', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## a generic method for unpacking fonts:
##
## * TTF
## * OTF
##
## These fonts have a similar structure, but differ in the magic
## header and the required tables.
def unpackFont(filename, offset, unpackdir, temporarydirectory, requiredtables, fontextension, fonttype, collectionoffset=None):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    checkfile = open(filename, 'rb')

    ## skip the magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then the number of tables
    checkbytes = checkfile.read(2)
    numtables = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    if numtables == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False, 'reason': 'no tables defined'}
        return {'status': False, 'error': unpackingerror}

    ## followed by the searchRange
    checkbytes = checkfile.read(2)
    searchrange = int.from_bytes(checkbytes, byteorder='big')

    ## the search range is defined
    ## as (maximum power of 2 <= numTables)*16
    if pow(2, int(math.log2(numtables)))*16 != searchrange:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'number of tables does not correspond to search range'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## then the entryselector, which is defined
    ## as log2(maximum power of 2 <= numTables)
    checkbytes = checkfile.read(2)
    entryselector = int.from_bytes(checkbytes, byteorder='big')
    if int(math.log2(numtables)) != entryselector:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'number of tables does not correspond to entrySelector'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## then the rangeshift
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

    ## There are fonts that are not 4 byte aligned. Computing checksums
    ## for these is more difficult, as it is unclear whether or not
    ## padding should be added or not.
    ## https://lists.w3.org/Archives/Public/public-webfonts-wg/2010Jun/0063.html
    ##
    ## For the checksums in individual tables it is imperative to add
    ## a few "virtual NUL bytes" to make sure that the checksum can be
    ## computed correctly. However, this doesn't seem to be working for
    ## the checkSumAdjustment value.

    addbytes = 0
    fontname = ''

    ## then read the table directory, with one entry per table
    for i in range(0,numtables):
        ## first the table name
        tablename = checkfile.read(4)
        if len(tablename) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table name'}
            return {'status': False, 'error': unpackingerror}

        ## each table can only appear once
        if tablename in tablesseen:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'duplicate table name'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        tablesseen.add(tablename)

        ## store the checksum for this table to check later
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table checksum'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        tablechecksum = int.from_bytes(checkbytes, byteorder='big')

        ## then the offset to the actual data
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table offset'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        tableoffset = int.from_bytes(checkbytes, byteorder='big')

        ## store where the data for each table starts
        tablenametooffset[tablename] = tableoffset

        ## then the length of the data
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for table length'}
            return {'status': False, 'error': unpackingerror}
        tablelength = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        if collectionoffset != None:
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

        ## then compute the checksum for the table
        ## First store the old offset, so it is possible
        ## to return.
        oldoffset = checkfile.tell()
        if collectionoffset != None:
            checkfile.seek(collectionoffset + tableoffset)
        else:
            checkfile.seek(offset + tableoffset)
        padding = 0

        ## tables are 4 byte aligned (long)
        if tablelength % 4 != 0:
            padding = 4 - tablelength % 4

        bytesadded = False

        ## extra sanity check, as there might now be padding bytes
        checkbytes = checkfile.read(tablelength + padding)
        if len(checkbytes) != tablelength + padding:
            if len(checkbytes) == tablelength:
                checkbytes += b'\x00' * padding
                addbytes = padding
                bytesadded = True
            else:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table'}
                return {'status': False, 'error': unpackingerror}

        ## parse the name table to see if there is a font name
        ## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6name.html
        if tablename == b'name':
            localoffset = 0
            if len(checkbytes) < 6:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data in name table'}
                return {'status': False, 'error': unpackingerror}

            ## first the format selector ("set to 0"). Skip.
            ## then the name count to indicate how many name records
            ## (12 bytes each) are present in the name table
            namecount = int.from_bytes(checkbytes[2:4], byteorder='big')
            if len(checkbytes) < 6 + namecount * 12:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data in name table'}
                return {'status': False, 'error': unpackingerror}

            ## then the offset of the name table strings
            nametablestringoffset = int.from_bytes(checkbytes[4:6], byteorder='big')
            if len(checkbytes) < 6 + namecount * 12 + nametablestringoffset:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data in name table'}
                return {'status': False, 'error': unpackingerror}

            localoffset = 6
            for n in range(0, namecount):
                ## first platform id
                platformid = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                ## skip platform specific id and language id
                localoffset += 4

                ## then the nameid
                nameid = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                ## then the name length
                namelength = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                ## then the name offset
                nameoffset = int.from_bytes(checkbytes[localoffset:localoffset+2], byteorder='big')
                localoffset += 2

                ## extract the font name if it exists
                if namelength != 0:
                    if nameid == 6:
                        if platformid == 0 or platformid == 1:
                            fontname = checkbytes[nametablestringoffset+nameoffset:nametablestringoffset+nameoffset+namelength]
        computedsum = 0
        for i in range(0, tablelength + padding, 4):
            computedsum += int.from_bytes(checkbytes[i:i+4], byteorder='big')

        ## only grab the lowest 32 bits (4294967295 = (2^32)-1)
        computedsum = computedsum & 4294967295
        if tablename != b'head':
            if tablechecksum != computedsum:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'checksum for table incorrect'}
                return {'status': False, 'error': unpackingerror}
        else:
            ## the head table checksum is different and uses a
            ## checksum adjustment, which is documented here:
            ## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6head.html
            ## First seek to the start of the table and then skip 8 bytes
            if collectionoffset != None:
                checkfile.seek(collectionoffset + tableoffset + 8)
            else:
                checkfile.seek(offset + tableoffset + 8)
            checkbytes = checkfile.read(4)
            checksumadjustment = int.from_bytes(checkbytes, byteorder='big')

        ## then store the maxoffset, including padding, but minus
        ## any "virtual" bytes
        if bytesadded:
            if collectionoffset != None:
                maxoffset = max(maxoffset, collectionoffset + tableoffset + tablelength + padding - addbytes)
            else:
                maxoffset = max(maxoffset, offset + tableoffset + tablelength + padding - addbytes)
        else:
            if collectionoffset != None:
                maxoffset = max(maxoffset, collectionoffset + tableoffset + tablelength + padding)
            else:
                maxoffset = max(maxoffset, offset + tableoffset + tablelength + padding)

        ## and return to the old offset for the next entry
        checkfile.seek(oldoffset)

    ## first check if all the required tables are there.
    if not tablesseen.intersection(requiredtables) == requiredtables:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not all required tables present'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = maxoffset - offset

    ## in case the file is a font collection it ends here.
    if collectionoffset != None:
        checkfile.close()
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## now compute the checksum for the whole font. It is important
    ## that checkSumAdjustment is set to 0 during this computation.
    ## It should be noted that for some fonts (where padding was added
    ## to the last table) this computation might be wrong.
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

    ## only grab the lowest 32 bits (4294967295 = (2^32)-1)
    fontchecksum = fontchecksum & 4294967295

    if checksumadjustment != 0xB1B0AFBA - fontchecksum:
        ## some fonts, such as the the Ubuntu ones use a different
        ## value for checksumadjustment
        if checksumadjustment != 0x1B1B0AFBA - fontchecksum:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'checksum adjustment does not match computed value'}
            return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('font')
        labels.append('resource')
        labels.append(fonttype)
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    ## if the name was extracted from the 'name' table it could possibly
    ## be used for the extracted file.
    if fontname != '':
        try:
            fontname = fontname.decode()
            outfilename = os.path.join(unpackdir, fontname + "." + fontextension)
        except:
            outfilename = os.path.join(unpackdir, "unpacked." + fontextension)
    else:
        outfilename = os.path.join(unpackdir, "unpacked." + fontextension)

    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    unpackedfilesandlabels.append((outfilename, ['font', 'resource', 'unpacked', fonttype]))
    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html
def unpackTrueTypeFont(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## font header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid font file'}
        return {'status': False, 'error': unpackingerror}

    ## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html
    ## (table 2)
    ## the following tables are required in a font:
    requiredtables = set([b'cmap', b'glyf', b'head', b'hhea', b'hmtx',
                          b'loca', b'maxp', b'name', b'post'])

    return unpackFont(filename, offset, unpackdir, temporarydirectory, requiredtables, 'ttf', 'TrueType')

## https://docs.microsoft.com/en-us/typography/opentype/spec/otff
def unpackOpenTypeFont(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## font header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid font file'}
        return {'status': False, 'error': unpackingerror}

    ## https://docs.microsoft.com/en-us/typography/opentype/spec/otff
    ## (section 'Font Tables')
    ## the following tables are required in a font:
    requiredtables = set([b'cmap', b'head', b'hhea', b'hmtx',
                          b'maxp', b'name', b'OS/2', b'post'])

    return unpackFont(filename, offset, unpackdir, temporarydirectory, requiredtables, 'otf', 'OpenType')

## Multiple fonts can be stored in font collections. The offsets
## recorded in the fonts are relative to the start of the collection
## not to the font itself.
## https://docs.microsoft.com/en-us/typography/opentype/spec/otff
def unpackOpenTypeFontCollection(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## https://docs.microsoft.com/en-us/typography/opentype/spec/otff
    ## (section 'Font Tables')
    ## the following tables are required in a font:
    requiredtables = set([b'cmap', b'head', b'hhea', b'hmtx',
                          b'maxp', b'name', b'OS/2', b'post'])

    ## font collection header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid font file'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize = 4

    ## major version, only support version 1 right now
    checkbytes = checkfile.read(2)
    majorversion = int.from_bytes(checkbytes, byteorder='big')
    if majorversion != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported major version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## minor version, has to be 0
    checkbytes = checkfile.read(2)
    minorversion = int.from_bytes(checkbytes, byteorder='big')
    if minorversion != 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported minor version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## number of fonts
    checkbytes = checkfile.read(4)
    numfonts = int.from_bytes(checkbytes, byteorder='big')
    if numfonts == 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no fonts declared'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    maxoffset = 0

    ## offsets for each font
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
        fontres = unpackFont(filename, offset + fontoffset, unpackdir, temporarydirectory, requiredtables, 'otf', 'OpenType', collectionoffset=offset)
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

## method to see if a file is a Vim swap file
## These always start with a certain header, including a page size.
##
## struct block0 in memline.c (Vim source code) describes the on disk
## format.
## Various other structs (data block, pointer block) are also described
## in this file.
def unpackVimSwapfile(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    checkfile = open(filename, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(6)
    if len(checkbytes) != 6:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}
    if checkbytes != b'b0VIM\x20':
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid Vim swap file header'}
        return {'status': False, 'error': unpackingerror}

    checkfile.seek(12)
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for page size'}
        return {'status': False, 'error': unpackingerror}

    pagesize = int.from_bytes(checkbytes, byteorder='little')

    ## TODO: enable carving.
    if filesize % pagesize != 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid Vim swap file'}
        return {'status': False, 'error': unpackingerror}

    ## then step through the blocks and check the first two
    ## characters of each block. There are two types of blocks: data
    ## blocks and pointer blocks.
    for i in range(1,filesize//pagesize):
        checkfile.seek(i*pagesize)
        checkbytes = checkfile.read(2)
        if not checkbytes in [b'tp', b'ad']:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid Vim swap file block identifier'}
            return {'status': False, 'error': unpackingerror}

    ## else consider it a Vim swap file
    labels.append('binary')
    labels.append('vim swap')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Some Android firmware updates are distributed as sparse data images.
## Given a data image and a transfer list data on an Android device is
## block wise added, replaced, erased, or zeroed.
##
## The Android sparse data image format is documented in the Android
## source code tree:
##
## https://android.googlesource.com/platform/bootable/recovery/+/master/updater/blockimg.cpp#1838
##
## Test files can be downloaded from LineageOS, for example:
##
## lineage-14.1-20180410-nightly-FP2-signed.zip
##
## Note: this is different to the Android sparse image format.
def unpackAndroidSparseData(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    ## for each .new.dat file there has to be a corresponding
    ## .transfer.list file as well.
    transferfile = filename.parent / (filename.name[:-8] + ".transfer.list")
    if not transferfile.exists():
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'transfer list not found'}
        return {'status': False, 'error': unpackingerror}

    ## open the transfer list in text mode, not in binary mode
    transferlist = open(transferfile, 'r')
    transferlistlines = list(map(lambda x: x.strip(), transferlist.readlines()))
    transferlist.close()

    if len(transferlistlines) < 4:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough entries in transer list'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize = 0

    ## first line is the version number, see comment here:
    ## https://android.googlesource.com/platform/bootable/recovery/+/master/updater/blockimg.cpp#1628
    try:
        versionnumber = int(transferlistlines[0])
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid transfer list version number'}
        return {'status': False, 'error': unpackingerror}

    if versionnumber != 4:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'only transfer list version 4 supported'}
        return {'status': False, 'error': unpackingerror}

    ## the next line is the amount of blocks (1 block is 4096 bytes)
    ## that will be copied to the output. This does not necessarily
    ## anything about the size of the output file as it might not include
    ## the blocks such as erase or zero, so it can be safely ignored.
    try:
        outputblocks = int(transferlistlines[1])
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid number for blocks to be written'}
        return {'status': False, 'error': unpackingerror}

    ## then two lines related to stash entries which are only used by
    ## Android during updates to prevent flash space from overflowing,
    ## so can safely be ignored here.
    try:
        stashneeded = int(transferlistlines[2])
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid number for simultaneous stash entries needed'}
        return {'status': False, 'error': unpackingerror}

    try:
        maxstash = int(transferlistlines[2])
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid number for maximum stash entries'}
        return {'status': False, 'error': unpackingerror}

    ## a list of commands recognized
    validtransfercommands = set(['new', 'zero', 'erase', 'free', 'stash'])

    transfercommands = []

    ## store the maximum block number
    maxblock = 0

    ## then parse the rest of the lines to see if they are valid
    for l in transferlistlines[4:]:
        transfersplit = l.split(' ')
        if len(transfersplit) != 2:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid line in transfer list'}
            return {'status': False, 'error': unpackingerror}
        (transfercommand, transferblocks) = transfersplit
        if not transfercommand in validtransfercommands:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unsupported command in transfer list'}
            return {'status': False, 'error': unpackingerror}
        transferblockssplit = transferblocks.split(',')
        if len(transferblockssplit)%2 == 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        ## first entry is the number of blocks on the rest of line
        try:
            transferblockcount = int(transferblockssplit[0])
        except:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        if not transferblockcount == len(transferblockssplit[1:]):
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        ## then check the rest of the numbers
        try:
            blocks = []
            for b in transferblockssplit[1:]:
                blocknr = int(b)
                blocks.append(blocknr)
                maxblock = max(maxblock, blocknr)
        except:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid transfer block list in transfer list'}
            return {'status': False, 'error': unpackingerror}
        ## store the transfer commands
        transfercommands.append((transfercommand, blocks))

    ## block size is set to 4096 in the Android source code
    blocksize = 4096

    ## cut the extension '.new.dat' from the file name unless the file
    ## name is the extension (as there would be a zero length name).
    if len(filename.stem) == 0:
        outputfilename = os.path.join(unpackdir, "unpacked-from-android-sparse-data")
    else:
        outputfilename = os.path.join(unpackdir, filename.stem)

    ## first create the targetfile
    targetfile = open(outputfilename, 'wb')

    ## make sure that the target file is large enough.
    ## On Linux truncate() will zero fill the targetfile.
    targetfile.truncate(maxblock*blocksize)

    ## then seek to the beginning of the target file
    targetfile.seek(0)

    ## open the source file
    checkfile = open(filename, 'rb')

    checkfile.seek(0)

    ## then process all the commands. "zero" is not interesting as
    ## the underlying file has already been zero filled.
    ## erase is not very interesting either.
    for c in transfercommands:
        (transfercommand, blocks) = c
        if transfercommand == 'new':
            for b in range(0,len(blocks),2):
                targetfile.seek(blocks[b]*blocksize)
                os.sendfile(targetfile.fileno(), checkfile.fileno(), None, (blocks[b+1] - blocks[b]) * blocksize)
        else:
            pass

    targetfile.close()
    checkfile.close()

    unpackedsize = filesize

    labels += ['androidsparsedata']
    unpackedfilesandlabels.append((outputfilename, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Android backup files
##
## Description of the format here:
##
## https://nelenkov.blogspot.nl/2012/06/unpacking-android-backups.html
## http://web.archive.org/web/20180425072922/https://nelenkov.blogspot.nl/2012/06/unpacking-android-backups.html
##
## header + zlib compressed data
## zlib compressed data contains a POSIX tar file
def unpackAndroidBackup(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    checkfile = open(filename, 'rb')

    ## skip over the offset
    checkfile.seek(offset+15)
    unpackedsize += 15

    ## Then read the version number. Only support version 1 right now.
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

    ## Then read the compression flag.
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

    ## Then read the encryption flag. Only "none" is supported,
    ## so read 5 bytes (including newline)
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

    ## create a temporary file to write the results to
    ## then create a zlib decompression object
    tempbackupfile = tempfile.mkstemp(dir=temporarydirectory)
    decompressobj = zlib.decompressobj()

    ## read 1 MB chunks
    chunksize = 1024*1024
    checkbytes = checkfile.read(chunksize)
    try:
        while checkbytes != b'':
            ## uncompress the data, and write to an output file
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

    ## now unpack the tar ball
    tarresult = unpackTar(pathlib.Path(tempbackupfile[1]), 0, unpackdir, temporarydirectory)

    ## cleanup
    os.unlink(tempbackupfile[1])
    if not tarresult['status']:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'corrupt tar inside Android backup file'}
        return {'status': False, 'error': unpackingerror}
    if not tarfilesize == tarresult['length']:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'corrupt tar inside Android backup file'}
        return {'status': False, 'error': unpackingerror}

    ## add the labels and pass on the results from the tar unpacking
    labels.append('android backup')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': tarresult['filesandlabels']}

## https://en.wikipedia.org/wiki/ICO_%28file_format%29
def unpackICO(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## header is 6 bytes
    if offset + 6 > filesize:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for ICO header'}
        return {'status': False, 'error': unpackingerror}

    ## open the file, skip the magic and read the number of images
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## read the number of images
    checkbytes = checkfile.read(2)
    numberofimages = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## there has to be at least 1 image
    if numberofimages == 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no images defined'}
        return {'status': False, 'error': unpackingerror}

    ## each ICONDIRENTRY in the ICONDIR is 16 bytes
    if offset + unpackedsize + numberofimages*16 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for ICONDIR entries'}
        return {'status': False, 'error': unpackingerror}

    ## store an in memory representation of the icon dir
    icondir = {}

    maxoffset = -1
    iconcounter = 1
    for i in range(0, numberofimages):
        ## read the image width
        checkbytes = checkfile.read(1)
        imagewidth = ord(checkbytes)
        if imagewidth == 0:
            imagewidth = 256
        unpackedsize += 1

        ## read the image height
        checkbytes = checkfile.read(1)
        imageheight = ord(checkbytes)
        if imageheight == 0:
            imageheight = 256
        unpackedsize += 1

        ## skip 6 bytes
        checkfile.seek(6, os.SEEK_CUR)
        unpackedsize += 6

        ## read the size of the image
        checkbytes = checkfile.read(4)
        imagesize = int.from_bytes(checkbytes, byteorder='little')

        ## image size cannot be 0
        if imagesize == 0:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'wrong size for image data'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then read the offset of the data
        checkbytes = checkfile.read(4)
        imageoffset = int.from_bytes(checkbytes, byteorder='little')

        ## image cannot be outside of the file
        if offset + imageoffset + imagesize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'image outside of file'}
            return {'status': False, 'error': unpackingerror}

        ## offset cannot be inside the header
        if imageoffset < checkfile.tell() - offset:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'wrong offset for image data'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## store the maximum offset of the end of each entry in the
        ## ICO. These will most likely be sequential, but maybe not.
        maxoffset = max(maxoffset, offset + imageoffset + imagesize)

        ## store the old offset
        oldoffset = checkfile.tell()

        ## jump to the location of the image data
        checkfile.seek(offset + imageoffset)
        checkbytes = checkfile.read(8)
        if checkbytes == b'\x89PNG\x0d\x0a\x1a\x0a':
            ## the file is a PNG
            icondir[iconcounter] = {'type': 'png', 'offset': imageoffset,
                                    'size': imagesize, 'width': imagewidth,
                                    'height': imageheight}
        else:
            ## the file is a BMP
            ## check the DIB header
            dibheadersize = int.from_bytes(checkbytes[:2], byteorder='little')
            if not dibheadersize in set([12, 64, 16, 40, 52, 56, 108, 124]):
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid DIB header size'}
                return {'status': False, 'error': unpackingerror}
            icondir[iconcounter] = {'type': 'bmp', 'offset': imageoffset,
                                    'size': imagesize, 'width': imagewidth,
                                    'height': imageheight}

        ## finally return to the old offset
        checkfile.seek(oldoffset)
        iconcounter += 1

    unpackedsize = maxoffset - offset

    if offset == 0 and unpackedsize == filesize:
        labels.append('graphics')
        labels.append('ico')
        labels.append('resource')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    outfilename = os.path.join(unpackdir, "unpacked.ico")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((outfilename, ['ico', 'graphics', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Chrome PAK
##
## version 4:
## http://dev.chromium.org/developers/design-documents/linuxresourcesandlocalizedstrings
##
## version 5:
## https://chromium.googlesource.com/chromium/src/tools/grit/+/master/grit/format/data_pack.py
def unpackChromePak(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## minimum for version 4: version + number of resources + encoding
    ## + 2 zero bytes + end of last file = 15
    ##
    ## minimum for version 5: version + encoding + 3 padding bytes
    ##  + number of resources + number of aliases = 12
    if filesize < 12:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'file too small'}
        return {'status': False, 'error': unpackingerror}
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)

    ## first the version number
    checkbytes = checkfile.read(4)
    pakversion = int.from_bytes(checkbytes, byteorder='little')
    if pakversion != 4 and pakversion != 5:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'unsupported .pak version (can only process version 4 or 5)'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    if pakversion == 4:
        ## then the number of resources in the file
        checkbytes = checkfile.read(4)
        paknumberofresources = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        ## then the encoding
        checkbytes = checkfile.read(1)
        pakencoding = ord(checkbytes)
        unpackedsize += 1

        ## then all the resources
        for p in range(0, paknumberofresources):
            ## resource id
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for resource id'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for resource offset'}
                return {'status': False, 'error': unpackingerror}
            resourceoffset = int.from_bytes(checkbytes, byteorder='little')
            if resourceoffset + offset > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'resource offset outside file'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4

        ## two zero bytes
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for zero bytes'}
            return {'status': False, 'error': unpackingerror}
        if checkbytes != b'\x00\x00':
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'incorrect value for zero bytes'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## the "end of file" value
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for end of file'}
            return {'status': False, 'error': unpackingerror}
        endoffile = int.from_bytes(checkbytes, byteorder='little')

        if endoffile + offset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'end of file cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}

    elif pakversion == 5:
        ## read the encoding
        checkbytes = checkfile.read(1)
        pakencoding = ord(checkbytes)
        unpackedsize += 1

        ## skip three bytes
        checkfile.seek(3, os.SEEK_CUR)
        unpackedsize += 3

        ## then the number of resources
        checkbytes = checkfile.read(2)
        paknumberofresources = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        ## then the number of aliases
        checkbytes = checkfile.read(2)
        paknumberofaliases = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 2

        ## then all the resources
        for p in range(0, paknumberofresources):
            ## resource id
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for resource id'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for resource offset'}
                return {'status': False, 'error': unpackingerror}
            resourceoffset = int.from_bytes(checkbytes, byteorder='little')
            if resourceoffset + offset > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'resource offset outside file'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4

        ## extra entry at the end with the end of file
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for resource id'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data for end of file'}
            return {'status': False, 'error': unpackingerror}
        endoffile = int.from_bytes(checkbytes, byteorder='little')

        ## then all the aliases
        for p in range(0, paknumberofaliases):
            ## resource id
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for resource id'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for resource offset'}
                return {'status': False, 'error': unpackingerror}
            aliasresourceoffset = int.from_bytes(checkbytes, byteorder='little')
            if aliasresourceoffset + offset > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'resource offset outside file'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4

    if endoffile + offset == filesize:
        checkfile.close()
        labels.append('binary')
        labels.append('resource')
        labels.append('pak')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    outfilename = os.path.join(unpackdir, "unpacked-from-pak")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, endoffile - offset)
    outfile.close()
    unpackedfilesandlabels.append((outfilename, ['binary', 'resource', 'pak', 'unpacked']))
    checkfile.close()

    labels.append('binary')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## The on disk format for GNU message catalog files is described here:
## https://www.gnu.org/software/gettext/manual/gettext.html#index-file-format_002c-_002emo
##
## The extension for these files is often '.mo'
def unpackGNUMessageCatalog(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## header has at least 20 bytes
    if filesize - offset < 20:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for GNU message catalog header'}
        return {'status': False, 'error': unpackingerror}

    bigendian = False

    checkfile = open(filename, 'rb')
    checkfile.seek(offset)
    ## first check the header to see if the file is big endian
    ## or little endian.
    checkbytes = checkfile.read(4)
    if checkbytes == b'\x95\x04\x12\xde':
        bigendian = True
    unpackedsize += 4

    ## then the version. The "major version" can only be 0 or 1
    checkbytes = checkfile.read(4)
    if bigendian:
        version = int.from_bytes(checkbytes, byteorder='big')
    else:
        version = int.from_bytes(checkbytes, byteorder='little')
    if (version >> 16) > 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unknown GNU message catalog version number'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## then the message count
    checkbytes = checkfile.read(4)
    if bigendian:
        message_count = int.from_bytes(checkbytes, byteorder='big')
    else:
        message_count = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## followed by the offset of the id of the original strings
    checkbytes = checkfile.read(4)
    if bigendian:
        textoffsets = int.from_bytes(checkbytes, byteorder='big')
    else:
        textoffsets = int.from_bytes(checkbytes, byteorder='little')

    ## the offset for the original strings cannot be outside of the file
    if offset + textoffsets > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for start of original texts'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## followed by the offset of the id of the translations
    checkbytes = checkfile.read(4)
    if bigendian:
        translationoffsets = int.from_bytes(checkbytes, byteorder='big')
    else:
        translationoffsets = int.from_bytes(checkbytes, byteorder='little')

    ## the offset for the translations cannot be outside of the file
    if offset + translationoffsets > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for start of original texts'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    maxoffset = checkfile.tell()

    ## now verify if the locations of the original strings and
    ## the translations are valid.
    for i in range(0,message_count):
        ## Check ids, first the location of the original
        checkfile.seek(offset+textoffsets+i*8)
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+textoffsets, 'fatal': False,
                              'reason': 'not enough data for message entry'}
            return {'status': False, 'error': unpackingerror}

        if bigendian:
            ## not sure if this is correct
            (messagelength, messageoffset) = struct.unpack('>II', checkbytes)
        else:
            (messagelength, messageoffset) = struct.unpack('<II', checkbytes)

        ## end of the original string cannot be outside of the file
        if offset + messageoffset + messagelength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+textoffsets, 'fatal': False,
                              'reason': 'not enough data for message entry'}
            return {'status': False, 'error': unpackingerror}

        maxoffset = max(maxoffset, checkfile.tell(), offset + messageoffset + messagelength)

        ## then the location of the translation
        checkfile.seek(offset+translationoffsets+i*8)
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+textoffsets, 'fatal': False,
                              'reason': 'not enough data for message entry'}
            return {'status': False, 'error': unpackingerror}
        if bigendian:
            (messagelength, messageoffset) = struct.unpack('>II', checkbytes)
        else:
            (messagelength, messageoffset) = struct.unpack('<II', checkbytes)

        ## end of the translated string cannot be outside of the file
        if offset + messageoffset + messagelength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+textoffsets, 'fatal': False,
                              'reason': 'not enough data for message entry'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(offset+messageoffset)
        checkbytes = checkfile.read(messagelength)

        ## is it NUL terminated? If not read an extra byte
        ## and check if it is NUL
        if not checkbytes[-1] == b'\x00':
            checkbytes = checkfile.read(1)
            if checkbytes != b'\x00':
                checkfile.close()
                unpackingerror = {'offset': offset+textoffsets, 'fatal': False,
                                  'reason': 'entry not NUL terminated'}
                return {'status': False, 'error': unpackingerror}
        maxoffset = max(maxoffset, checkfile.tell())

    unpackedsize = checkfile.tell() - offset

    ## see if the whole file is a GNU message catalog
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('binary')
        labels.append('resource')
        labels.append('GNU message catalog')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file
    outfilename = os.path.join(unpackdir, "unpacked-from-message-catalog")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    unpackedfilesandlabels.append((outfilename, ['binary', 'resource', 'GNU message catalog', 'unpacked']))
    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://en.wikipedia.org/wiki/Cabinet_(file_format)
##
## Microsoft has documented the file format here:
##
## https://msdn.microsoft.com/en-us/library/bb267310.aspx#struct_spec
##
## but is currently not under the open specification promise
def unpackCab(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## there are 33 bytes for all mandatory cab headers
    if filesize < 33:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip the magic and reserved field
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    ## check the filesize
    checkbytes = checkfile.read(4)
    cabinetsize = int.from_bytes(checkbytes, byteorder='little')
    if cabinetsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'defined cabinet size larger than file'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('cabextract') == None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'cabextract program not found'}
        return {'status': False, 'error': unpackingerror}

    havetmpfile = False
    if not (offset == 0 and filesize == cabinetsize):
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, cabinetsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True

    checkfile.close()
    if havetmpfile:
        p = subprocess.Popen(['cabextract', '-d', unpackdir, temporaryfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(['cabextract', '-d', unpackdir, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        if havetmpfile:
            os.unlink(temporaryfile[1])
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid cab file'}
        return {'status': False, 'error': unpackingerror}
    checkfile.close()

    unpackedsize = cabinetsize - offset

    dirwalk = os.walk(unpackdir)
    for direntries in dirwalk:
        ## make sure all subdirectories and files can be accessed
        for subdir in direntries[1]:
            subdirname = os.path.join(direntries[0], subdir)
            if not os.path.islink(subdirname):
                os.chmod(subdirname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
        for filename in direntries[2]:
            fullfilename = os.path.join(direntries[0], filename)
            unpackedfilesandlabels.append((fullfilename, []))

    if not havetmpfile:
        labels.append('cab')
        labels.append('archive')

    ## cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## SGI file format
## https://media.xiph.org/svt/SGIIMAGESPEC
def unpackSGI(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    if filesize - offset < 512:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for SGI header'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    ## skip over the magic
    checkfile.seek(offset+2)
    unpackedsize += 2

    ## next the storage byte
    checkbytes = checkfile.read(1)
    if not (ord(checkbytes) == 0 or ord(checkbytes) == 1):
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for storage format'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1
    if ord(checkbytes) == 0:
        storageformat = 'verbatim'
    else:
        storageformat = 'rle'

    ## next the bytes per pixel channel
    checkbytes = checkfile.read(1)
    bytesperpixel = ord(checkbytes)
    if not (bytesperpixel == 1 or bytesperpixel == 2):
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for BPC'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## next the dimensions. The only allowed values are 1, 2, 3
    checkbytes = checkfile.read(2)
    dimensions = int.from_bytes(checkbytes, byteorder='big')
    if not dimensions in [1,2,3]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for dimensions'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## next xsize, ysize and zsize
    checkbytes = checkfile.read(2)
    xsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    checkbytes = checkfile.read(2)
    ysize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    checkbytes = checkfile.read(2)
    zsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    ## pinmin and pinmax
    checkbytes = checkfile.read(4)
    pinmin = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    checkbytes = checkfile.read(4)
    pinmax = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## 4 bytes of dummy data, always 0x00
    checkbytes = checkfile.read(4)
    if not checkbytes == b'\x00' * 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for dummy bytes in header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## image name, NUL terminated
    checkbytes = checkfile.read(80)
    imagename = checkbytes.split(b'\x00')[0]
    unpackedsize += 80

    ## colormap, can be 0, 1, 2, 3
    checkbytes = checkfile.read(4)
    colormap = int.from_bytes(checkbytes, byteorder='big')
    if not colormap in [0,1,2,3]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for colormap'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## last 404 bytes of the header should be 0x00
    checkfile.seek(offset+108)
    checkbytes = checkfile.read(404)
    if checkbytes != b'\x00' * 404:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for dummy bytes in header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 404

    if storageformat == 'verbatim':
        ## if storage format is verbatim then an image basically
        ## header + (width + height + depth * bytes per pixel)
        imagelength = 512 + xsize * ysize * zsize * bytesperpixel
        if imagelength > filesize - offset:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough image data'}
            return {'status': False, 'error': unpackingerror}
        if offset == 0 and imagelength == filesize:
            ## now load the file into PIL as an extra sanity check
            try:
                testimg = PIL.Image.open(checkfile)
                testimg.load()
                testimg.close()
            except:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid SGI according to PIL'}
                return {'status': False, 'error': unpackingerror}
            checkfile.close()

            labels.append('sgi')
            labels.append('graphics')
            return {'status': True, 'length': imagelength, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        ## Carve the image.
        ## first reset the file pointer
        checkfile.seek(offset)

        ## in case a name was recorded in the file and it
        ## is not the name given by pnmtosgi use the recorded
        ## name of the file. Otherwise use a default name.
        if len(imagename) != 0 and imagename.decode() != "no name":
            outfilename = os.path.join(unpackdir, imagename.decode())
        else:
            outfilename = os.path.join(unpackdir, "unpacked.sgi")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, imagelength)
        outfile.close()
        checkfile.close()

        ## reopen as read only
        outfile = open(outfilename, 'rb')

        ## now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(outfile)
            testimg.load()
            testimg.close()
            outfile.close()
        except:
            outfile.close()
            os.unlink(outfilename)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid SGI according to PIL'}
            return {'status': False, 'error': unpackingerror}

        unpackedfilesandlabels.append((outfilename, ['sgi', 'graphics', 'unpacked']))
        return {'status': True, 'length': imagelength, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## now unpack the LRE format
    ## There should be two tables: starttab and lengthtab
    ## store the table with offsets
    starttab = {}
    for n in range(0,ysize*zsize):
        checkbytes = checkfile.read(4)
        if not len(checkbytes) == 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for RLE start table'}
            return {'status': False, 'error': unpackingerror}
        starttabentry = int.from_bytes(checkbytes, byteorder='big')
        starttab[n] = starttabentry
        unpackedsize += 4

    maxoffset = 0
    for n in range(0,ysize*zsize):
        checkbytes = checkfile.read(4)
        if not len(checkbytes) == 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for RLE length table'}
            return {'status': False, 'error': unpackingerror}
        lengthtabentry = int.from_bytes(checkbytes, byteorder='big')

        ## check if the data is outside of the file
        if offset + starttab[n] + lengthtabentry > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for RLE data'}
            return {'status': False, 'error': unpackingerror}
        maxoffset = max(maxoffset, starttab[n] + lengthtabentry)
        unpackedsize += 4

    unpackedsize = maxoffset

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('sgi')
        labels.append('graphics')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## Carve the image.
    ## first reset the file pointer
    checkfile.seek(offset)
    outfilename = os.path.join(unpackdir, "unpacked.sgi")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['sgi', 'graphics', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Derived from specifications linked at:
## https://en.wikipedia.org/wiki/Audio_Interchange_File_Format
##
## AIFF-C:
## https://web.archive.org/web/20071219035740/http://www.cnpbagwell.com/aiff-c.txt
##
## Test files in any recent Python 3 distribution in Lib/test/audiodata/
def unpackAIFF(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Too small for AIFF or AIFF-C file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename, 'rb')
    ## skip over the header
    checkfile.seek(offset+4)
    checkbytes = checkfile.read(4)
    chunkdatasize = int.from_bytes(checkbytes, byteorder='big')

    ## check if the file has enough bytes to be a valid AIFF or AIFF-C
    if offset + chunkdatasize + 8 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'chunk size bigger than file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    checkbytes = checkfile.read(4)

    if not (checkbytes == b'AIFF' or checkbytes == b'AIFC'):
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong form type'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    if checkbytes == b'AIFF':
        aifftype = 'aiff'
    else:
        aifftype = 'aiff-c'

    ## keep track of which chunk names have been seen, as a few are
    ## mandatory.
    chunknames = set()

    ## then read the respective chunks
    while checkfile.tell() < offset + 8 + chunkdatasize:
        chunkid = checkfile.read(4)
        if len(chunkid) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for chunk id'}
            return {'status': False, 'error': unpackingerror}
        ## store the name of the chunk, as a few chunk names are mandatory
        chunknames.add(chunkid)
        unpackedsize += 4

        ## read the size of the chunk
        checkbytes = checkfile.read(4)
        if len(chunkid) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for chunk'}
            return {'status': False, 'error': unpackingerror}
        chunksize = int.from_bytes(checkbytes, byteorder='big')
        ## chunk sizes should be even, so add a padding byte if necessary
        if chunksize % 2 != 0:
            chunksize += 1
        ## check if the chunk isn't outside of the file
        if checkfile.tell() + chunksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'declared chunk size outside file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        checkfile.seek(chunksize, os.SEEK_CUR)
        unpackedsize += chunksize

    ## chunks "COMM" and "SSND" are mandatory
    if not b'COMM' in chunknames:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Mandatory chunk \'COMM\' not found.'}
        return {'status': False, 'error': unpackingerror}
    if not b'SSND' in chunknames:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Mandatory chunk \'SSND\' not found.'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels += ['audio', 'aiff', aifftype]
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked-aiff")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['audio', 'aiff', 'unpacked', aifftype]))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## terminfo files, format described in the Linux man page for terminfo files
## man 5 term
def unpackTerminfo(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## the header is 12 bytes long
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    ## first skip over the magic
    checkfile.seek(offset+2)
    unpackedsize += 2

    ## the size of the names section, which immediately follows the header
    checkbytes = checkfile.read(2)
    namessectionsize = int.from_bytes(checkbytes, byteorder='little')
    ## check if the names section is inside the file
    if offset + 12 + namessectionsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid value for names section or not enough data'}
        return {'status': False, 'error': unpackingerror}
    if namessectionsize < 2:
        ## man page says:
        ## "this section is terminated with an ASCII NUL character"
        ## so it cannot be empty. The name of the terminal has to be
        ## at least one character.
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'names section size cannot be less than 2'}
        return {'status': False, 'error': unpackingerror}

    ## name field cannot exceed 128 bytes
    if namessectionsize > 128:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid names section size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## the number of bytes in the boolean section,
    ## which follows the names section
    checkbytes = checkfile.read(2)
    booleansize = int.from_bytes(checkbytes, byteorder='little')
    if offset + 12 + namessectionsize + booleansize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid value for boolean bytes or not enough data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## the number section has to start on an even byte boundary
    ## so pad if necessary.
    booleanpadding = 0
    if (12 + namessectionsize + booleansize)%2 != 0:
        booleanpadding = 1

    ## the number of short integers in the numbers section,
    ## following the boolean section
    checkbytes = checkfile.read(2)
    numbershortints = int.from_bytes(checkbytes, byteorder='little')
    if offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid value for short ints or not enough data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## the number of shorts in the strings section,
    ## following the numbers section
    checkbytes = checkfile.read(2)
    stringoffsets = int.from_bytes(checkbytes, byteorder='little')
    if offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2 + stringoffsets*2> filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid value for string offsets or not enough data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    stringstableoffset = offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2 + stringoffsets*2

    ## the size of the string table following the strings section
    checkbytes = checkfile.read(2)
    stringstablesize = int.from_bytes(checkbytes, byteorder='little')
    if stringstableoffset + stringstablesize> filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid value for strings table or not enough data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## names in the namessection size have to be printable.
    checkfile.seek(offset + 12)
    checkbytes = checkfile.read(namessectionsize)
    for n in checkbytes[:-1]:
        if not chr(n) in string.printable:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid character in names section'}
            return {'status': False, 'error': unpackingerror}

    ## skip to the end of the namessection and check if there is a NUL
    if checkbytes[-1] != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'names section not terminated with NUL'}
        return {'status': False, 'error': unpackingerror}

    ## first skip to the start of the boolean section
    ## and check all the booleans
    checkfile.seek(offset + 12 + namessectionsize)
    for n in range(0,booleansize):
        checkbytes = checkfile.read(1)
        if checkbytes != b'\x00' and checkbytes != b'\x01':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid value for boolean table entry'}
            return {'status': False, 'error': unpackingerror}

    maxoffset = -1

    ## then check each of the offsets from the string offsets section
    ## in the strings table. This doesn't work well for some terminfo
    ## files, such as jfbterm, kon, kon2, screen.xterm-xfree86
    ## probably due to wide character support.
    checkfile.seek(offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2)
    for n in range(0,stringoffsets):
        checkbytes = checkfile.read(2)
        if checkbytes == b'\xff\xff':
            continue
        stringoffset = int.from_bytes(checkbytes, byteorder='little')
        if stringstableoffset + stringoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': unpackedsize, 'fatal': False,
                              'reason': 'invalid offset for string table entry'}
            return {'status': False, 'error': unpackingerror}
        maxoffset = max(maxoffset, stringstableoffset + stringoffset)

    ## then skip to the end of the string table
    checkfile.seek(stringstableoffset + stringstablesize)
    unpackedsize = stringstableoffset + stringstablesize - offset

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('terminfo')
        labels.append('resource')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## possibly there are extensions
    if filesize - checkfile.tell() >= 10:
        validextension = True
        ## first make sure to start on an even byte boundary
        localunpackedsize = 0
        if (checkfile.tell() - offset)%2 != 0:
            localunpackedsize += 1
            checkfile.seek(1, os.SEEK_CUR)

        ## read the extended booleans capabilities
        checkbytes = checkfile.read(2)
        extendedboolean = int.from_bytes(checkbytes, byteorder='little')
        localunpackedsize += 2

        ## read the extended numeric capabilities
        checkbytes = checkfile.read(2)
        extendednumeric = int.from_bytes(checkbytes, byteorder='little')
        localunpackedsize += 2

        ## read the extended string capabilities
        checkbytes = checkfile.read(2)
        extendedstringcap = int.from_bytes(checkbytes, byteorder='little')
        localunpackedsize += 2

        ## read the extended string table size
        checkbytes = checkfile.read(2)
        extendedstringsize = int.from_bytes(checkbytes, byteorder='little')
        localunpackedsize += 2

        ## read the location of the last offset in
        ## the extended string table
        checkbytes = checkfile.read(2)
        laststringoffset = int.from_bytes(checkbytes, byteorder='little')
        localunpackedsize += 2
        if laststringoffset == 0:
            validextension = False

        ## read the extended booleans
        if validextension:
            for n in range(0, extendedboolean):
                checkbytes = checkfile.read(1)
                if checkbytes != b'\x00' and checkbytes != b'\x01':
                    validextension = False
                    break
                localunpackedsize += 1

        ## pad on even boundary
        if (checkfile.tell() - offset)%2 != 0:
            localunpackedsize += 1
            checkfile.seek(1, os.SEEK_CUR)

        ## read the extended numeric capabilities
        if validextension:
            checkbytes = checkfile.read(extendednumeric*2)
            if len(checkbytes) != extendednumeric*2:
                validextension = False
            localunpackedsize += extendednumeric*2

        ## check each of the string offsets
        if validextension:
            maxoffset = -1
            for n in range(0,extendedstringcap):
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                    validextension = False
                    break
                localunpackedsize += 2
                if checkbytes == b'\xff\xff':
                    continue
                stringoffset = int.from_bytes(checkbytes, byteorder='little')

        ## Then finally read the string table.
        if validextension:
            checkbytes = checkfile.read(extendedstringsize)
            if len(checkbytes) != extendedstringsize:
                validextension = False
            localunpackedsize += extendedstringsize

        ## There is also a (NUL?) byte for each number and boolean.
        ##
        ## compare _nc_read_termtype() from ncurses/tinfo/read_entry.c
        ## from the ncurses 6.1 release.
        ##
        ## Easy hack: use the last offset in the string table
        if validextension:
            checkbytes = checkfile.read(extendedboolean + extendednumeric)
            if len(checkbytes) != extendedboolean + extendednumeric:
                validextension = False
            ## there might be a NUL byte, but this doesn't hold for
            ## every file seen in the wild so ignore for now.
            #if not checkbytes == b'\x00' * (extendedboolean + extendednumeric):
            #        validextension = False
            if validextension:
                checkbytes = checkfile.read(laststringoffset)
                if len(checkbytes) != laststringoffset:
                    validextension = False
                localunpackedsize += laststringoffset
                if checkbytes[-1] != 0:
                    validextension = False

        if validextension:
            unpackedsize = checkfile.tell() - offset

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('terminfo')
        labels.append('resource')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## else carve.
    checkfile.seek(offset)
    outfilename = os.path.join(unpackdir, "unpacked-from-term")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['terminfo', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://rzip.samba.org/
## https://en.wikipedia.org/wiki/Rzip
def unpackRzip(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 10:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 10 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('rzip') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'rzip program not found'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename, 'rb')

    ## skip over the header
    checkfile.seek(offset+4)
    unpackedsize = 4

    ## then read the major version
    checkbytes = checkfile.read(1)
    unpackedsize += 1

    if ord(checkbytes) > 2:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid major version number %d' % ord(checkbytes)}
        return {'status': False, 'error': unpackingerror}

    ## then read the minor version
    checkbytes = checkfile.read(1)
    unpackedsize += 1

    ## then read the size of the uncompressed data
    checkbytes = checkfile.read(4)
    uncompressedsize = int.from_bytes(checkbytes, byteorder='big')

    ## check if there actually is bzip2 compressed data.
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

        ## no bzip2 data was found, so it is not a valid rzip file
        if not bzip2headerfound:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no valid bzip2 header found'}
            return {'status': False, 'error': unpackingerror}

        ## uncompress the bzip2 data
        bzip2res = unpackBzip2(filename, bzip2pos, unpackdir, temporarydirectory, dryrun=True)
        if not bzip2res['status']:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no valid bzip2 data'}
            return {'status': False, 'error': unpackingerror}

        checkfile.seek(bzip2pos + bzip2res['length'])
        unpackedsize = checkfile.tell() - offset

        ## check if there could be another block with bzip2 data
        ## the data between the bzip2 blocks is 13 bytes, see
        ## rzip source code, file: stream.c, function: fill_buffer()
        if filesize - (bzip2res['length'] + bzip2pos) < 13:
            break

        checkfile.seek(13, os.SEEK_CUR)
        checkbytes = checkfile.read(3)
        if checkbytes != b'BZh':
            break

        checkfile.seek(-3, os.SEEK_CUR)

    if not filename.suffix.lower() == '.rz':
        outfilename = os.path.join(unpackdir, "unpacked-from-rzip")
    else:
        outfilename = os.path.join(unpackdir, filename.stem)

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        p = subprocess.Popen(['rzip', '-k', '-d', filename, '-o', outfilename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid RZIP file'}
            return {'status': False, 'error': unpackingerror}
        if os.stat(outfilename).st_size != uncompressedsize:
            os.unlink(outfilename)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unpacked RZIP data does not match declared uncompressed size'}
            return {'status': False, 'error': unpackingerror}
        unpackedfilesandlabels.append((outfilename, []))
        labels.append('compressed')
        labels.append('rzip')

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    else:
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        checkfile.close()
        p = subprocess.Popen(['rzip', '-d', temporaryfile[1], '-o', outfilename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            os.unlink(temporaryfile[1])
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid RZIP file'}
            return {'status': False, 'error': unpackingerror}
        if os.stat(outfilename).st_size != uncompressedsize:
            os.unlink(outfilename)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'unpacked RZIP data does not match declared uncompressed size'}
            return {'status': False, 'error': unpackingerror}
        unpackedfilesandlabels.append((outfilename, []))

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

## Derived from specifications at:
## https://en.wikipedia.org/wiki/Au_file_format
##
## Test files in any recent Python 3 distribution in Lib/test/audiodata/
def unpackAU(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    if filesize - offset < 24:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Too small for AU file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename, 'rb')

    ## skip over the header
    checkfile.seek(offset+4)
    checkbytes = checkfile.read(4)
    dataoffset = int.from_bytes(checkbytes, byteorder='big')
    if dataoffset % 8 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data offset not divisible by 8'}
        return {'status': False, 'error': unpackingerror}
    if offset + dataoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data offset cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    ## read the length
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    ## only support files that have the data size embedded in the header
    if checkbytes != b'\xff\xff\xff\xff':
        datasize = int.from_bytes(checkbytes, byteorder='big')

        ## According to Wikipedia and the OpenGroup just a limited
        ## number of encodings are in use
        checkbytes = checkfile.read(4)
        encoding = int.from_bytes(checkbytes, byteorder='big')
        if not encoding in set([1,2,3,4,5,6,7,8,9,10,11,12,13,18,19,20,21,23,24,25,26,27]):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong encoding value'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## skip over sample rate
        checkbytes = checkfile.read(4)
        unpackedsize += 4

        ## skip over channels
        checkbytes = checkfile.read(4)
        unpackedsize += 4

        ## there is an optional information chunk, ignore for now
        ## the data offset has to follow the header
        if dataoffset < checkfile.tell() - offset:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'data offset cannot start inside header'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(offset + dataoffset)
        unpackedsize = dataoffset

        ## there has to be enough data for the audio
        if offset + dataoffset + datasize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'AU data cannot be outside of file'}
            return {'status': False, 'error': unpackingerror}

        ## finally the data, just skip over it
        unpackedsize += datasize
        if offset == 0 and unpackedsize == filesize:
            checkfile.close()
            labels += ['audio', 'au']
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        ## else carve the file. It is anonymous, so give it a name
        outfilename = os.path.join(unpackdir, "unpacked-au")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((outfilename, ['audio', 'au', 'unpacked']))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## default case: nothing unpacked
    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'Cannot determine size for AU file'}
    return {'status': False, 'error': unpackingerror}

## JFFS2 https://en.wikipedia.org/wiki/JFFS2
## JFFS2 is a file system that was used on earlier embedded Linux
## system, although it is no longer the first choice for modern systems,
## where for example UBI/UBIFS are chosen.
def unpackJFFS2(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 12 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)

    bigendian = False

    ## read the magic of the first inode to see if it is a little endian
    ## or big endian file system
    checkbytes = checkfile.read(2)
    if checkbytes == b'\x19\x85':
        bigendian = True

    dataunpacked = False

    ## keep track of which nodes have already been seen. This is to
    ## detect if multiple JFFS2 file systems have been concatenated.
    ## Also store the version, as inodes could have been reused in the
    ## case of hardlinks.
    inodesseenversion = set()
    parentinodesseen = set()

    ## the various node types are:
    ##
    ## * directory entry
    ## * inode (containing actual data)
    ## * clean marker
    ## * padding
    ## * summary
    ## * xattr
    ## * xref
    ##
    ## For unpacking data only the directory entry and regular inode
    ## will be considered.

    DIRENT = 0xe001
    INODE = 0xe002
    CLEANMARKER = 0x2003
    PADDING = 0x2004
    SUMMARY = 0x2006
    XATTR = 0xe008
    XREF = 0xe009

    validinodes = set([DIRENT, INODE, CLEANMARKER,
                       PADDING, SUMMARY, XATTR, XREF])

    inodetoparent = {}

    ## keep a list of inodes to file names
    ## the root inode (1) always has ''
    inodetofilename = {}
    inodetofilename[1] = ''

    ## different kinds of compression
    ## Jefferson ( https://github.com/sviehb/jefferson ) defines more
    ## types than standard JFFS2. LZMA compression is available as a
    ## patch from OpenWrt.
    COMPR_NONE = 0x00
    COMPR_ZERO = 0x01
    COMPR_RTIME = 0x02
    COMPR_RUBINMIPS = 0x03
    COMPR_COPY = 0x04
    COMPR_DYNRUBIN = 0x05
    COMPR_ZLIB = 0x06
    COMPR_LZO = 0x07
    COMPR_LZMA = 0x08

    ## LZMA settings from OpenWrt's patch
    lzma_dict_size = 0x2000
    lzma_pb = 0
    lzma_lp = 0
    lzma_lc = 0

    ## keep a mapping of inodes to last written position in
    ## the file.
    inodetowriteoffset = {}

    ## a mapping of inodes to open files
    inodetoopenfiles = {}

    rootseen = False

    ## reset the file pointer and read all the inodes
    checkfile.seek(offset)
    while True:
        oldoffset = checkfile.tell()
        if checkfile.tell() == filesize:
            break
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            break

        ## first check if the inode magic is valid
        if bigendian:
            if not checkbytes in [b'\x19\x85', b'\x00\x00', b'\xff\xff']:
                break
        else:
            if not checkbytes in [b'\x85\x19', b'\x00\x00', b'\xff\xff']:
                break
        if checkbytes == b'\x00\x00':
            ## dirty nodes, skip.
            nodemagictype = 'dirty'
        elif checkbytes == b'\xff\xff':
            ## empty space
            unpackedsize += 2
            paddingbytes = 0x10000 - (unpackedsize%0x10000)
            if paddingbytes != 0:
                checkbytes = checkfile.read(paddingbytes)
                if len(checkbytes) != paddingbytes:
                    break
                unpackedsize += paddingbytes
            continue
        else:
            nodemagictype = 'normal'
        unpackedsize += 2

        ## then read the node type
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            break
        if bigendian:
            inodetype = int.from_bytes(checkbytes, byteorder='big')
        else:
            inodetype = int.from_bytes(checkbytes, byteorder='little')

        ## check if the inode type is actually valid
        if not inodetype in validinodes:
            break

        ## then read the size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            break
        if bigendian:
            inodesize = int.from_bytes(checkbytes, byteorder='big')
        else:
            inodesize = int.from_bytes(checkbytes, byteorder='little')

        ## check if the inode extends past the file
        if checkfile.tell() - 12 + inodesize > filesize:
            break

        ## skip dirty nodes
        if nodemagictype == 'dirty':
            checkfile.seek(oldoffset + inodesize)
            unpackedsize = checkfile.tell() - offset
            if unpackedsize % 4 != 0:
                paddingbytes = 4 - (unpackedsize%4)
                checkfile.seek(paddingbytes, os.SEEK_CUR)
                unpackedsize = checkfile.tell() - offset
            continue

        ## then the header CRC of the first 8 bytes in the node
        ## The checksum is not the same as the CRC32 algorithm from
        ## zlib/binascii, and it is explained here:
        ##
        ## http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            break
        if bigendian:
            headercrc = int.from_bytes(checkbytes, byteorder='big')
        else:
            headercrc = int.from_bytes(checkbytes, byteorder='little')

        ## The checksum varies slightly from the one in the zlib/binascii modules
        ## as explained here:
        ##
        ## http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
        ##
        ## specific implementation for computing checksum grabbed from
        ## MIT licensed script found at:
        ##
        ## https://github.com/sviehb/jefferson/blob/master/src/scripts/jefferson
        checkfile.seek(-12, os.SEEK_CUR)
        checkbytes = checkfile.read(8)

        computedcrc = (binascii.crc32(checkbytes, -1) ^ -1) & 0xffffffff
        if not computedcrc == headercrc:
            break

        ## skip past the CRC and start processing the data
        checkfile.seek(4, os.SEEK_CUR)
        unpackedsize = checkfile.tell() - offset

        ## process directory entries
        if inodetype == DIRENT:
            ## parent inode is first
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            if bigendian:
                parentinode = int.from_bytes(checkbytes, byteorder='big')
            else:
                parentinode = int.from_bytes(checkbytes, byteorder='little')

            parentinodesseen.add(parentinode)

            ## inode version is next
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            if bigendian:
                inodeversion = int.from_bytes(checkbytes, byteorder='big')
            else:
                inodeversion = int.from_bytes(checkbytes, byteorder='little')

            ## inode number is next
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            if bigendian:
                inodenumber = int.from_bytes(checkbytes, byteorder='big')
            else:
                inodenumber = int.from_bytes(checkbytes, byteorder='little')

            ## skip unlinked inodes
            if inodenumber == 0:
                ## first go back to the old offset, then skip
                ## the entire inode
                checkfile.seek(oldoffset + inodesize)
                unpackedsize = checkfile.tell() - offset
                if unpackedsize % 4 != 0:
                    paddingbytes = 4 - (unpackedsize%4)
                    checkfile.seek(paddingbytes, os.SEEK_CUR)
                    unpackedsize = checkfile.tell() - offset
                continue

            ## cannot have duplicate inodes
            if (inodenumber, inodeversion) in inodesseenversion:
                break

            inodesseenversion.add((inodenumber, inodeversion))

            ## mctime is next, not interesting so no need to process
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break

            ## name length is next
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                break
            inodenamelength = ord(checkbytes)
            if inodenamelength == 0:
                break

            ## the dirent type is next. Not sure what to do with this
            ## value at the moment
            checkbytes = checkfile.read(1)
            if len(checkbytes) != 1:
                break

            ## skip two unused bytes
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break

            ## the node CRC. skip for now
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break

            ## the name CRC
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            if bigendian:
                namecrc = int.from_bytes(checkbytes, byteorder='big')
            else:
                namecrc = int.from_bytes(checkbytes, byteorder='little')

            ## finally the name of the node
            checkbytes = checkfile.read(inodenamelength)
            if len(checkbytes) != inodenamelength:
                break

            try:
                inodename = checkbytes.decode()
            except:
                break

            ## compute the CRC of the name
            computedcrc = (binascii.crc32(checkbytes, -1) ^ -1) & 0xffffffff
            if namecrc !=  computedcrc:
                break

            ## process any possible hard links
            if inodenumber in inodetofilename:
                ## the inode number is already known, meaning
                ## that this should be a hard link
                os.link(os.path.join(unpackdir, inodetofilename[inodenumber]), os.path.join(unpackdir, inodename))

                ## TODO: determine whether or not to add
                ## the hard link to the result set
                ## unpackedfilesandlabels.append((os.path.join(unpackdir, inodename),['hardlink']))

            ## now add the name to the inode to filename mapping
            if parentinode in inodetofilename:
                inodetofilename[inodenumber] = os.path.join(inodetofilename[parentinode], inodename)

        elif inodetype == INODE:
            ## inode number
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            if bigendian:
                inodenumber = int.from_bytes(checkbytes, byteorder='big')
            else:
                inodenumber = int.from_bytes(checkbytes, byteorder='little')

            ## first check if a file name for this inode is known
            if not inodenumber in inodetofilename:
                break

            ## skip unlinked inodes
            if inodenumber == 0:
                ## first go back to the old offset, then skip
                ## the entire inode
                checkfile.seek(oldoffset + inodesize)
                unpackedsize = checkfile.tell() - offset
                if unpackedsize % 4 != 0:
                    paddingbytes = 4 - (unpackedsize%4)
                    checkfile.seek(paddingbytes, os.SEEK_CUR)
                    unpackedsize = checkfile.tell() - offset
                continue

            ## version number, should not be a duplicate
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            if bigendian:
                inodeversion = int.from_bytes(checkbytes, byteorder='big')
            else:
                inodeversion = int.from_bytes(checkbytes, byteorder='little')

            ## file mode
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            if bigendian:
                filemode = int.from_bytes(checkbytes, byteorder='big')
            else:
                filemode = int.from_bytes(checkbytes, byteorder='little')

            if stat.S_ISSOCK(filemode):
                ## keep track of whatever is in the file and report
                pass
            elif stat.S_ISDIR(filemode):
                ## create directories, but skip them otherwise
                os.makedirs(os.path.join(unpackdir, inodetofilename[inodenumber]))
                checkfile.seek(oldoffset + inodesize)
                continue
            elif stat.S_ISLNK(filemode):
                ## skip ahead 24 bytes to the size of the data
                checkfile.seek(24, os.SEEK_CUR)

                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                if bigendian:
                    linknamelength = int.from_bytes(checkbytes, byteorder='big')
                else:
                    linknamelength = int.from_bytes(checkbytes, byteorder='little')

                ## skip ahead 16 bytes to the data containing the link name
                checkfile.seek(16, os.SEEK_CUR)
                checkbytes = checkfile.read(linknamelength)
                if len(checkbytes) != linknamelength:
                    break
                try:
                    os.symlink(checkbytes.decode(), os.path.join(unpackdir, inodetofilename[inodenumber]))
                    unpackedfilesandlabels.append((os.path.join(unpackdir, inodetofilename[inodenumber]),['symbolic link']))
                    dataunpacked = True
                except Exception as e:
                    break
            elif stat.S_ISREG(filemode):
                ## skip ahead 20 bytes to the offset of where to write data
                checkfile.seek(20, os.SEEK_CUR)

                ## the write offset is useful as a sanity check: either
                ## it is 0, or it is the previous offset, plus the
                ## previous uncompressed length.
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                if bigendian:
                    writeoffset = int.from_bytes(checkbytes, byteorder='big')
                else:
                    writeoffset = int.from_bytes(checkbytes, byteorder='little')

                if writeoffset == 0:
                    if inodenumber in inodetowriteoffset:
                        break
                    if inodenumber in inodetoopenfiles:
                        break
                    ## open a file and store it as a reference
                    outfile = open(os.path.join(unpackdir, inodetofilename[inodenumber]), 'wb')
                    inodetoopenfiles[inodenumber] = outfile
                else:
                    if writeoffset != inodetowriteoffset[inodenumber]:
                        break
                    if not inodenumber in inodetoopenfiles:
                        break
                    outfile = inodetoopenfiles[inodenumber]

                ## the offset to the compressed data length
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                if bigendian:
                    compressedsize = int.from_bytes(checkbytes, byteorder='big')
                else:
                    compressedsize = int.from_bytes(checkbytes, byteorder='little')

                ## read the decompressed size
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                    break
                if bigendian:
                    decompressedsize = int.from_bytes(checkbytes, byteorder='big')
                else:
                    decompressedsize = int.from_bytes(checkbytes, byteorder='little')

                ## find out which compression algorithm has been used
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                    break
                compression_used = ord(checkbytes)

                ## skip ahead 11 bytes to the actual data
                checkfile.seek(11, os.SEEK_CUR)
                checkbytes = checkfile.read(compressedsize)
                if len(checkbytes) != compressedsize:
                    break

                ## Check the compression that's used as it could be that
                ## for a file compressed and uncompressed nodes are mixed
                ## in case the node cannot be compressed efficiently
                ## and the compressed data would be larger than the
                ## original data.
                if compression_used == COMPR_NONE:
                    ## the data is not compressed, so can be written
                    ## to the output file immediately
                    outfile.write(checkbytes)
                    dataunpacked = True
                elif compression_used == COMPR_ZLIB:
                    ## the data is zlib compressed, so first decompress
                    ## before writing
                    try:
                        outfile.write(zlib.decompress(checkbytes))
                        dataunpacked = True
                    except Exception as e:
                        break
                elif compression_used == COMPR_LZMA:
                    ## The data is LZMA compressed, so create a
                    ## LZMA decompressor with custom filter, as the data
                    ## is stored without LZMA headers.
                    jffs_filters = [
                         {"id": lzma.FILTER_LZMA1, "dict_size": lzma_dict_size, 'lc': lzma_lc, 'lp': lzma_lp, 'pb': lzma_pb},
                    ]

                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=jffs_filters)

                    try:
                        outfile.write(decompressor.decompress(checkbytes))
                        dataunpacked = True
                    except Exception as e:
                        break
                #elif compression_used == COMPR_LZO:
                ## The JFFS2 version of LZO somehow cannot be unpacked with
                ## python-lzo
                else:
                    break
                inodetowriteoffset[inodenumber] = writeoffset + decompressedsize
            else:
                ## unsure what to do here now
                pass

        checkfile.seek(oldoffset + inodesize)
        unpackedsize = checkfile.tell() - offset
        if unpackedsize % 4 != 0:
            paddingbytes = 4 - (unpackedsize%4)
            checkfile.seek(paddingbytes, os.SEEK_CUR)
            unpackedsize = checkfile.tell() - offset

    checkfile.close()

    if not dataunpacked:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no data unpacked'}
        return {'status': False, 'error': unpackingerror}

    ## close all the open files
    for i in inodetoopenfiles:
        inodetoopenfiles[i].flush()
        inodetoopenfiles[i].close()
        unpackedfilesandlabels.append((inodetoopenfiles[i].name,[]))

    ## check if a valid root node was found.
    if not 1 in parentinodesseen:
        for i in inodetoopenfiles:
            os.unlink(inodetoopenfiles[i])
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no valid root file node'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and filesize == unpackedsize:
        labels.append('jffs2')
        labels.append('file system')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## An unpacker for various CPIO flavours.
## A description of the CPIO format can be found in section 5 of the
## cpio manpage on Linux:
## man 5 cpio
##
## This unpacker allows partial unpacking of (corrupt) cpio archives
## TODO: make partial unpacking optional
## TODO: return better errors
##
## Some CPIO files, such as made on Solaris, that pack special
## device files such as doors and event ports, might fail to
## unpack on Linux.
## See https://bugs.python.org/issue11016 for background information
## about event ports, doors and whiteout files.
def unpackCpio(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## old binary format has a 26 byte header
    ## portable ASCII format has a 76 byte header
    ## new formats have a 110 byte header
    if filesize - offset < 26:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes for header'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    checkfile.seek(offset)

    dataunpacked = False
    trailerfound = False

    ## chunksize for reading data for checksum
    chunksize = 1024*1024

    ## keep track of devices and inodes to properly process
    ## hard links
    devinodes = {}
    counter = 0

    ## now process each entry inside the CPIO file
    ## store the CPIO type and use it as an extra check
    ## as a CPIO file can only have one CPIO type. For
    ## extreme weird edge cases this can be disabled.
    cpiotype = None
    stricttypecheck = True

    ## keep track of where the latest successful
    ## offset where data was unpacked was, since
    ## it might be necessary to rewind in case data could
    ## only be unpacked partially.
    latestsuccessfuloffset = -1

    while checkfile.tell() < filesize:
        checkbytes = checkfile.read(6)
        if len(checkbytes) != 6:
            break

        if cpiotype == None:
            if not checkbytes.startswith(b'\xc7\x71'):
                cpiotype = checkbytes
            else:
                cpiotype = checkbytes[0:2]
        elif stricttypecheck and cpiotype != checkbytes:
            if not checkbytes.startswith(b'\xc7\x71'):
                break

        isdevice = False
        possibletrailer = False

        ## the header is a bit different based on the type
        ## 070707 == portable ASCII format
        ## 070701 == new ASCII format
        ## 070702 == new CRC format
        ## 0xc771 == old binary format, only little endian supported
        if cpiotype.startswith(b'\xc7\x71'):
            ## first rewind 4 bytes
            checkfile.seek(-4, os.SEEK_CUR)
            unpackedsize += 2

            ## look ahead to see if this is possibly a trailer
            checkbytes =  os.pread(checkfile.fileno(), 10, checkfile.tell() + 24)
            if checkbytes == b'TRAILER!!!':
                possibletrailer = True

            ## dev
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            try:
                dev = int.from_bytes(checkbytes, byteorder='little')
            except:
                break
            unpackedsize += 2

            ## inode
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            try:
                inode = int.from_bytes(checkbytes, byteorder='little')
            except:
                break
            ## every file, even special files, have an
            ## associated inode
            if inode == 0:
                possibletrailer = True
            unpackedsize += 2

            ## mode
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            try:
                cpiomode = int.from_bytes(checkbytes, byteorder='little')
            except:
                break
            if not possibletrailer:
                if cpiomode == 0:
                    break
                ## only support whatever is defined in the CPIO man page
                if cpiomode < 0o0010000:
                    break

                ## some checks to filter out false positives
                modes = set()

                isdir = False
                if stat.S_ISDIR(cpiomode):
                    isdir = True
                modes.add(isdir)

                isfile = False
                if stat.S_ISREG(cpiomode):
                    if True in modes:
                        break
                    isfile = True
                modes.add(isfile)

                islink = False
                if stat.S_ISLNK(cpiomode):
                    if True in modes:
                        break
                    islink = True
                modes.add(islink)

                isdevice = False
                if (stat.S_ISCHR(cpiomode) or stat.S_ISBLK(cpiomode)):
                    if True in modes:
                        break
                    isdevice = True
                modes.add(isdevice)

                isfifo = False
                if stat.S_ISFIFO(cpiomode):
                    if True in modes:
                        break
                    isfifo = True

                modes.add(isfifo)
                issocket = False
                if stat.S_ISSOCK(cpiomode):
                    if True in modes:
                        break
                    issocket = True
                modes.add(issocket)

                if not True in modes:
                    break

            unpackedsize += 2

            ## uid
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            unpackedsize += 2

            ## gid
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            unpackedsize += 2

            ## number of links
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            try:
                nr_of_links = int.from_bytes(checkbytes, byteorder='little')
            except:
                break
            unpackedsize += 2

            ## there should always be at least 1 link
            if nr_of_links == 0 and not possibletrailer:
                break

            ## rdev
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            try:
                rdev = int.from_bytes(checkbytes, byteorder='little')
            except:
                break
            ## "For all other entry types, it should be set to zero by
            ## writers and ignored by readers."
            #if rdev != 0:
            #        isdevice = True
            unpackedsize += 2

            ## mtime
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            unpackedsize += 4

            ## name size
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                break
            try:
                namesize = int.from_bytes(checkbytes, byteorder='little')
            except:
                break
            ## not possible to have an empty name
            if namesize == 0:
                break
            unpackedsize += 2

            ## file size. This is a bit trickier, as it is not one
            ## integer, but two shorts, with the most significant
            ## first.
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                break
            cpiodatasize = int.from_bytes(checkbytes[0:2], byteorder='little') * 65536
            cpiodatasize += int.from_bytes(checkbytes[2:4], byteorder='little')
            unpackedsize += 4

            ## data cannot be outside of the file
            if (offset + cpiodatasize + namesize) > filesize:
                break

            ## then read the file name
            checkbytes = checkfile.read(namesize)
            if len(checkbytes) != namesize:
                break
            if checkbytes == b'TRAILER!!!\x00':
                unpackedsize += namesize
                trailerfound = True

                ## if necessary add a padding byte
                if unpackedsize % 2 != 0:
                    padbytes = 1
                    checkbytes = checkfile.read(padbytes)
                    if len(checkbytes) != padbytes:
                        break
                    unpackedsize += padbytes
                break

            ## a real trailer would have been found, so if this point
            ## is reached, then the entry was not a trailer.
            if possibletrailer:
                break

            unpackedsize += namesize
            unpackname = checkbytes.split(b'\x00', 1)[0]
            if len(unpackname) == 0:
                break
            while os.path.isabs(unpackname):
                unpackname = unpackname[1:]
            if len(unpackname) == 0:
                break
            try:
                unpackname = unpackname.decode()
            except:
                break

            ## pad to even bytes
            if unpackedsize % 2 != 0:
                padbytes = 2 - unpackedsize%2
                checkbytes = checkfile.read(padbytes)
                if len(checkbytes) != padbytes:
                    break
                unpackedsize += padbytes
            checkfile.seek(offset+unpackedsize)

            ## then the data itself
            if isdevice:
                continue

            dataunpacked = True

            ## if it is a directory, then just create the directory
            if isdir:
                os.makedirs(os.path.join(unpackdir, unpackname), exist_ok=True)
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), []))
                continue
            ## first symbolic links
            if islink:
                if offset + unpackedsize + cpiodatasize > filesize:
                    break
                unpackdirname = os.path.dirname(unpackname)
                if unpackdirname != '':
                    os.makedirs(os.path.join(unpackdir, unpackdirname), exist_ok=True)
                checkbytes = checkfile.read(cpiodatasize)

                ## first a hack for embedded 0x00 in data
                targetname = checkbytes.split(b'\x00', 1)[0]
                try:
                    targetname = targetname.decode()
                except:
                    break

                os.symlink(targetname, os.path.join(unpackdir, unpackname))
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), ['symbolic link']))
            ## then regular files
            elif isfile:
                if offset + unpackedsize + cpiodatasize > filesize:
                    break
                ## first create the directory structure if necessary
                unpackdirname = os.path.dirname(unpackname)
                if unpackdirname != '':
                    os.makedirs(os.path.join(unpackdir, unpackdirname), exist_ok=True)
                outfile = open(os.path.join(unpackdir, unpackname), 'wb')
                os.sendfile(outfile.fileno(), checkfile.fileno(), offset+unpackedsize, cpiodatasize)
                outfile.close()
                if not (inode, dev) in devinodes:
                    devinodes[(inode, dev)] = []
                devinodes[(inode, dev)].append(unpackname)
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), []))
            unpackedsize += cpiodatasize

            ## pad to even bytes
            if unpackedsize % 2 != 0:
                padbytes = 2 - unpackedsize%2
                checkbytes = checkfile.read(padbytes)
                if len(checkbytes) != padbytes:
                    break
                unpackedsize += padbytes
            checkfile.seek(offset+unpackedsize)

        elif cpiotype == b'070707':
            if filesize - offset < 76:
                if not dataunpacked:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough bytes for header'}
                    return {'status': False, 'error': unpackingerror}
                break
            unpackedsize += 6

            ## look ahead to see if this is possibly a trailer
            checkbytes =  os.pread(checkfile.fileno(), 10, checkfile.tell() + 70)
            if checkbytes == b'TRAILER!!!':
                possibletrailer = True

            ## dev
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            try:
                dev = int(checkbytes, base=8)
            except:
                break
            unpackedsize += 6

            ## inode
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            try:
                inode = int(checkbytes, base=8)
            except:
                break
            unpackedsize += 6

            ## mode
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            try:
                cpiomode = int(checkbytes, base=8)
            except:
                break
            if not possibletrailer:
                ## the mode for any entry cannot be 0
                if cpiomode == 0:
                    break
                ## only support whatever is defined in the CPIO man page
                if cpiomode < 0o0010000:
                    break

                ## some checks to filter out false positives
                modes = set()

                isdir = False
                if stat.S_ISDIR(cpiomode):
                    isdir = True
                modes.add(isdir)

                isfile = False
                if stat.S_ISREG(cpiomode):
                    if True in modes:
                        break
                    isfile = True
                modes.add(isfile)

                islink = False
                if stat.S_ISLNK(cpiomode):
                    if True in modes:
                        break
                    islink = True
                modes.add(islink)

                isdevice = False
                if (stat.S_ISCHR(cpiomode) or stat.S_ISBLK(cpiomode)):
                    if True in modes:
                        break
                    isdevice = True
                modes.add(isdevice)

                isfifo = False
                if stat.S_ISFIFO(cpiomode):
                    if True in modes:
                        break
                    isfifo = True
                modes.add(isfifo)

                issocket = False
                if stat.S_ISSOCK(cpiomode):
                    if True in modes:
                        break
                    issocket = True
                modes.add(issocket)

                if not True in modes:
                    break
            unpackedsize += 6

            ## uid
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            unpackedsize += 6

            ## gid
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            unpackedsize += 6

            ## number of links
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            try:
                nr_of_links = int(checkbytes, base=8)
            except:
                break
            unpackedsize += 6

            ## there should always be at least 1 link
            if nr_of_links == 0 and not possibletrailer:
                break

            ## rdev
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            try:
                rdev = int(checkbytes, base=8)
            except:
                break
            ## "For all other entry types, it should be set to zero by
            ## writers and ignored by readers."
            #if rdev != 0:
            #        isdevice = True
            unpackedsize += 6

            ## check the cpio mode to see if there is a bogus
            ## value and this is actually not a cpio file
            if (stat.S_ISCHR(cpiomode) or stat.S_ISBLK(cpiomode)) and not possibletrailer:
                isdevice = True

            ## mtime
            checkbytes = checkfile.read(11)
            if len(checkbytes) != 11:
                break
            unpackedsize += 11

            ## name size
            checkbytes = checkfile.read(6)
            if len(checkbytes) != 6:
                break
            try:
                namesize = int(checkbytes, base=8)
            except:
                break
            if namesize == 0:
                break
            unpackedsize += 6

            ## file size
            checkbytes = checkfile.read(11)
            if len(checkbytes) != 11:
                break
            try:
                cpiodatasize = int(checkbytes, base=8)
            except:
                break
            unpackedsize += 11

            ## data cannot be outside of the file
            if (offset + namesize + cpiodatasize) > filesize:
                break

            ## then read the file name
            checkbytes = checkfile.read(namesize)
            if len(checkbytes) != namesize:
                break
            if checkbytes == b'TRAILER!!!\x00':
                unpackedsize += namesize
                trailerfound = True
                break

            ## a real trailer would have been found, so if this point
            ## is reached, then the entry was not a trailer.
            if possibletrailer:
                break

            unpackedsize += namesize
            unpackname = checkbytes.split(b'\x00', 1)[0]
            if len(unpackname) == 0:
                break
            while os.path.isabs(unpackname):
                unpackname = unpackname[1:]
            if len(unpackname) == 0:
                break
            namedecoded = False
            for c in encodingstotranslate:
               try:
                  unpackname = unpackname.decode(c)
                  namedecoded = True
                  break
               except Exception as e:
                  pass
            if not namedecoded:
               break

            ## then the data itself
            if isdevice:
                continue

            dataunpacked = True

            ## if it is a directory, then just create the directory
            if isdir:
                os.makedirs(os.path.join(unpackdir, unpackname), exist_ok=True)
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), []))
                continue
            ## first symbolic links
            if islink:
                if offset + unpackedsize + cpiodatasize > filesize:
                    break
                unpackdirname = os.path.dirname(unpackname)
                if unpackdirname != '':
                    os.makedirs(os.path.join(unpackdir, unpackdirname), exist_ok=True)
                checkbytes = checkfile.read(cpiodatasize)

                ## first a hack for embedded 0x00 in data
                targetname = checkbytes.split(b'\x00', 1)[0]
                try:
                    targetname = targetname.decode()
                except:
                    break

                os.symlink(targetname, os.path.join(unpackdir, unpackname))
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), ['symbolic link']))
            ## then regular files
            elif isfile:
                if offset + unpackedsize + cpiodatasize > filesize:
                    break
                ## first create the directory structure if necessary
                unpackdirname = os.path.dirname(unpackname)
                if unpackdirname != '':
                    os.makedirs(os.path.join(unpackdir, unpackdirname), exist_ok=True)
                outfile = open(os.path.join(unpackdir, unpackname), 'wb')
                os.sendfile(outfile.fileno(), checkfile.fileno(), offset+unpackedsize, cpiodatasize)
                outfile.close()
                if not (inode, dev) in devinodes:
                    devinodes[(inode, dev)] = []
                devinodes[(inode, dev)].append(unpackname)
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), []))
            unpackedsize += cpiodatasize
            checkfile.seek(offset+unpackedsize)

        elif cpiotype == b'070701' or b'070702':
            if filesize - offset < 110:
                if not dataunpacked:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'not enough bytes for header'}
                    return {'status': False, 'error': unpackingerror}
                break
            unpackedsize += 6

            ## look ahead to see if this is possibly a trailer
            checkbytes =  os.pread(checkfile.fileno(), 10, checkfile.tell() + 104)
            if checkbytes == b'TRAILER!!!':
                possibletrailer = True

            ## inode
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                inode = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            unpackedsize += 8

            ## mode
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                cpiomode = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            if not possibletrailer:
                ## the mode for any entry cannot be 0
                if cpiomode == 0:
                    break
                ## only support whatever is defined in the CPIO man page
                if cpiomode < 0o0010000:
                    break

                ## some checks to filter out false positives
                modes = set()

                isdir = False
                if stat.S_ISDIR(cpiomode):
                    isdir = True
                modes.add(isdir)

                isfile = False
                if stat.S_ISREG(cpiomode):
                    if True in modes:
                        break
                    isfile = True
                modes.add(isfile)

                islink = False
                if stat.S_ISLNK(cpiomode):
                    if True in modes:
                        break
                    islink = True
                modes.add(islink)

                isdevice = False
                if (stat.S_ISCHR(cpiomode) or stat.S_ISBLK(cpiomode)):
                    if True in modes:
                        break
                    isdevice = True
                modes.add(isdevice)

                isfifo = False
                if stat.S_ISFIFO(cpiomode):
                    if True in modes:
                        break
                    isfifo = True
                modes.add(isfifo)

                issocket = False
                if stat.S_ISSOCK(cpiomode):
                    if True in modes:
                        break
                    issocket = True
                modes.add(issocket)

                if not True in modes:
                    break
            unpackedsize += 8

            ## uid
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            unpackedsize += 8

            ## gid
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            unpackedsize += 8

            ## number of links
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                nr_of_links = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            unpackedsize += 8

            ## there should always be at least 1 link
            if nr_of_links == 0 and not possibletrailer:
                break

            ## mtime
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            unpackedsize += 8

            ## size of the cpio data.
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                cpiodatasize = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            unpackedsize += 8

            ## dev_major
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                devmajor = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            unpackedsize += 8

            ## dev_minor
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                devminor = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            unpackedsize += 8

            ## rdev_major
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                rdevmajor = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            ## "For all other entry types, it should be set to zero by
            ## writers and ignored by readers."
            ## Example: Glide3-20010520-13.i386.rpm from Red Hat 7.3
            #if rdevmajor != 0 and not possibletrailer:
            #        isdevice = True
            unpackedsize += 8

            ## rdev_minor
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                rdevminor = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            ## "For all other entry types, it should be set to zero by
            ## writers and ignored by readers."
            #if rdevminor != 0 and not possibletrailer:
            #        isdevice = True
            unpackedsize += 8

            ## check the cpio mode to see if there is a bogus
            ## value and this is actually not a cpio file
            if (stat.S_ISCHR(cpiomode) or stat.S_ISBLK(cpiomode)) and not possibletrailer:
                isdevice = True

            ## name size
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                namesize = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            ## not possible to have an empty name
            if namesize == 0:
                break
            unpackedsize += 8

            ## c_check
            checkbytes = checkfile.read(8)
            if len(checkbytes) != 8:
                break
            try:
                cpiochecksum = int.from_bytes(binascii.unhexlify(checkbytes), byteorder='big')
            except:
                break
            if cpiotype == b'070701' and not possibletrailer:
                ## for new ASCII format the checksum is always 0
                if cpiochecksum != 0:
                    break
            unpackedsize += 8

            ## data cannot be outside of the file
            if offset + namesize + cpiodatasize > filesize:
                break

            ## then read the file name
            checkbytes = checkfile.read(namesize)
            if len(checkbytes) != namesize:
                break
            if checkbytes == b'TRAILER!!!\x00':
                ## end of the archive has been reached,
                ## pad if necessary so unpacked size is a
                ## multiple of 4 bytes.
                unpackedsize += namesize
                trailerfound = True
                if unpackedsize % 4 != 0:
                    padbytes = 4 - unpackedsize%4
                    checkbytes = checkfile.read(padbytes)
                    if len(checkbytes) != padbytes:
                        break
                    unpackedsize += padbytes
                break

            ## a real trailer would have been found, so if this point
            ## is reached, then the entry was not a trailer.
            if possibletrailer:
                break
            unpackedsize += namesize
            unpackname = checkbytes.split(b'\x00', 1)[0]
            if len(unpackname) == 0:
                break
            while os.path.isabs(unpackname):
                unpackname = unpackname[1:]
            if len(unpackname) == 0:
                break
            namedecoded = False
            for c in encodingstotranslate:
               try:
                  unpackname = unpackname.decode(c)
                  namedecoded = True
                  break
               except Exception as e:
                  pass
            if not namedecoded:
               break

            ## add padding bytes as the entry has to be on a 4 byte boundary
            if unpackedsize % 4 != 0:
                padbytes = 4 - unpackedsize%4
                checkbytes = checkfile.read(padbytes)
                if len(checkbytes) != padbytes:
                    break
                unpackedsize += padbytes

            ## then the data itself
            if isdevice:
                continue

            ## if it is a directory, then just create the directory
            if isdir:
                dataunpacked = True
                os.makedirs(os.path.join(unpackdir, unpackname), exist_ok=True)
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), []))
                continue

            ## first symbolic links
            if islink:
                if offset + unpackedsize + cpiodatasize > filesize:
                    break
                unpackdirname = os.path.dirname(unpackname)
                if unpackdirname != '':
                    os.makedirs(os.path.join(unpackdir, unpackdirname), exist_ok=True)
                checkbytes = checkfile.read(cpiodatasize)

                ## first a hack for embedded 0x00 in data
                targetname = checkbytes.split(b'\x00', 1)[0]
                try:
                    targetname = targetname.decode()
                except:
                    break

                dataunpacked = True

                os.symlink(targetname, os.path.join(unpackdir, unpackname))
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), ['symbolic link']))
            ## then regular files
            elif isfile:
                if offset + unpackedsize + cpiodatasize > filesize:
                    break
                ## first create the directory structure if necessary
                unpackdirname = os.path.dirname(unpackname)
                if unpackdirname != '':
                    os.makedirs(os.path.join(unpackdir, unpackdirname), exist_ok=True)
                outfile = open(os.path.join(unpackdir, unpackname), 'wb')
                os.sendfile(outfile.fileno(), checkfile.fileno(), offset+unpackedsize, cpiodatasize)
                outfile.close()
                if not (inode, devmajor, devminor) in devinodes:
                    devinodes[(inode, devmajor, devminor)] = []
                devinodes[(inode, devmajor, devminor)].append(unpackname)
                unpackedfilesandlabels.append((os.path.join(unpackdir, unpackname), []))
                ## verify checksum
                if cpiotype == b'070702':
                    tmpchecksum = 0
                    outfile = open(os.path.join(unpackdir, unpackname), 'rb')
                    checkbytes = outfile.read(chunksize)
                    while checkbytes != b'':
                        for i in checkbytes:
                            tmpchecksum += i
                        checkbytes = outfile.read(chunksize)
                        tmpchecksum = tmpchecksum & 0xffffffff
                    outfile.close()
                    if cpiochecksum != tmpchecksum:
                        break
                dataunpacked = True

            unpackedsize += cpiodatasize

            ## add padding bytes as the entry has to be on a 4 byte boundary
            if unpackedsize % 4 != 0:
                padbytes = 4 - unpackedsize%4
                checkbytes = checkfile.read(padbytes)
                if len(checkbytes) != padbytes:
                    break
                unpackedsize += padbytes
            checkfile.seek(offset+unpackedsize)
        else:
            break

    ## now recreate the hard links
    for n in devinodes:
        if cpiotype == b'\xc7\x71':
            ## in the old cpio type hard links
            ## always store the same data
            continue
        if len(devinodes[n]) == 1:
            continue
        target = None
        for i in range(len(devinodes[n]),0,-1):
            if os.stat(os.path.join(unpackdir, devinodes[n][i-1])).st_size != 0:
                target = devinodes[n][i-1]
        if target == None:
            continue
        for i in range(len(devinodes[n]),0,-1):
            if devinodes[n][i-1] == target:
                continue
            linkname = os.path.join(unpackdir, devinodes[n][i-1])
            ## remove the empty file...
            os.unlink(linkname)
            ## ...and create hard link
            os.link(os.path.join(unpackdir, target), linkname)

    ## no trailer was found
    if not trailerfound:
        checkfile.close()
        if not dataunpacked:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid CPIO file'}
            return {'status': False, 'error': unpackingerror}
        ## no trailer was found, but data was unpacked, so tag the
        ## archive as corrupt and partially unpacked.
        labels.append("corrupt")
        labels.append("partially unpacked")
    else:
        ## cpio implementations tend to pad archives with
        ## NUL bytes to a multiple of 512 bytes
        ## but 256 is also used.
        havepadding = False
        padoffset = checkfile.tell()
        for i in [512, 256]:
            if unpackedsize % i != 0:
                paddingbytes = i - unpackedsize%i
                checkbytes = checkfile.read(paddingbytes)
                if len(checkbytes) == paddingbytes:
                    if checkbytes == paddingbytes * b'\x00':
                        unpackedsize += paddingbytes
                        havepadding = True
            if havepadding:
                break
            checkfile.seek(padoffset)
        checkfile.close()

    if offset == 0 and filesize == unpackedsize:
        labels.append('cpio')
        labels.append('archive')
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://en.wikipedia.org/wiki/7z
## Inside the 7z distribution there is a file called
##
## DOC/7zFormat.txt
##
## that describes the file format.
##
## This unpacker can recognize 7z formats, but only if the 7z file
## consists of a single frame.
def unpack7z(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## a 7z signature header is at least 32 bytes
    if filesize - offset < 32:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset + 6)
    unpackedsize += 6

    ## read the major version. This has been 0 for a long time.
    majorversion = ord(checkfile.read(1))
    if majorversion > 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid major version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## read the minor version
    minorversion = ord(checkfile.read(1))
    unpackedsize += 1

    ## read the CRC32 for the header
    checkbytes = checkfile.read(4)
    nextheadercrc = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    checkbytes = checkfile.read(20)
    if len(checkbytes) != 20:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}
    crccomputed = binascii.crc32(checkbytes)

    if nextheadercrc != crccomputed:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid header CRC'}
        return {'status': False, 'error': unpackingerror}

    ## first try to find the offset of the next header and read
    ## some metadata for it.
    nextheaderoffset = int.from_bytes(checkbytes[0:8], byteorder='little')
    nextheadersize = int.from_bytes(checkbytes[8:16], byteorder='little')
    nextheadercrc = int.from_bytes(checkbytes[16:20], byteorder='little')

    if checkfile.tell() + nextheaderoffset + nextheadersize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'next header offset outside file'}
        return {'status': False, 'error': unpackingerror}

    ## Then skip to the next offset
    checkfile.seek(checkfile.tell() + nextheaderoffset)

    ## extra sanity check: compute the header CRC for the
    ## next header...
    checkbytes = checkfile.read(nextheadersize)
    computedcrc = binascii.crc32(checkbytes)

    ## ...and compare it to the stored CRC
    if computedcrc != nextheadercrc:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid next header CRC'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = checkfile.tell() - offset

    if shutil.which('7z') == None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': '7z program not found'}
        return {'status': False, 'error': unpackingerror}

    havetmpfile = False
    if not (offset == 0 and filesize == unpackedsize):
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir, '-y', 'x', temporaryfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if offset == 0 and filesize == unpackedsize:
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir, '-y', 'x', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid 7z file'}
        return {'status': False, 'error': unpackingerror}

    dirwalk = os.walk(unpackdir)
    for direntries in dirwalk:
        ## make sure all subdirectories and files can be accessed
        for subdir in direntries[1]:
            subdirname = os.path.join(direntries[0], subdir)
            if not os.path.islink(subdirname):
                os.chmod(subdirname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
        for filename in direntries[2]:
            fullfilename = os.path.join(direntries[0], filename)
            unpackedfilesandlabels.append((fullfilename, []))

    ## cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])
    else:
        labels.append('7z')
        labels.append('compressed')
        labels.append('archive')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Windows Compiled HTML help
## https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help
## http://web.archive.org/web/20021209123621/www.speakeasy.org/~russotto/chm/chmformat.html
def unpackCHM(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## header has at least 56 bytes
    if filesize < 56:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip the magic and the version number
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    ## total header length
    checkbytes = checkfile.read(4)
    chmheaderlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + chmheaderlength > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'declared header outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## skip over the rest of the header
    checkfile.seek(offset + 56)
    unpackedsize = 56

    ## the header section table
    for i in range(0,2):
        ## a section offset
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for section offset'}
            return {'status': False, 'error': unpackingerror}
        sectionoffset = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 8

        ## and a section size
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for section size'}
            return {'status': False, 'error': unpackingerror}
        sectionsize = int.from_bytes(checkbytes, byteorder='little')

        ## sanity check: sections cannot be outside of the file
        if offset + sectionoffset + sectionsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'sections outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 8

    ## then the offset of content section 0, that isn't there in version 2,
    ## but version 2 is not supported anyway.
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

    ## then skip 8 bytes
    checkfile.seek(8, os.SEEK_CUR)
    unpackedsize += 8

    ## read the file size
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

    if shutil.which('7z') == None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': '7z program not found'}
        return {'status': False, 'error': unpackingerror}
    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'not a valid CHM file'}

    unpackedsize = chmsize

    havetmpfile = False
    if not (offset == 0 and filesize == unpackedsize):
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir, '-y', 'x', temporaryfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if offset == 0 and filesize == unpackedsize:
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir, '-y', 'x', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid CHM file'}
        return {'status': False, 'error': unpackingerror}

    dirwalk = os.walk(unpackdir)
    for direntries in dirwalk:
        ## make sure all subdirectories and files can be accessed
        for subdir in direntries[1]:
            subdirname = os.path.join(direntries[0], subdir)
            if not os.path.islink(subdirname):
                os.chmod(subdirname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
        for filename in direntries[2]:
            fullfilename = os.path.join(direntries[0], filename)
            unpackedfilesandlabels.append((fullfilename, []))

    ## cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])
    else:
        labels.append('chm')
        labels.append('compressed')
        labels.append('resource')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Windows Imaging Format
##
## This format has been described by Microsoft here:
##
## https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749478(v=ws.10)
##
## but is currently not under the open specification promise
##
## Windows data types can be found here:
## https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
def unpackWIM(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## a WIM signature header is at least 208 bytes
    if filesize - offset < 208:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset + 8)
    unpackedsize += 8

    ## now read the size of the header
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

    ## the WIM file format version, unused for now
    checkbytes = checkfile.read(4)
    wimversion = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## WIM flags, unused for now
    checkbytes = checkfile.read(4)
    wimflags = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## WIM compressed block size, can be 0, but most likely will be 32k
    checkbytes = checkfile.read(4)
    wimblocksize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## then the 16 byte WIM GUID
    wimguid = checkfile.read(16)
    unpackedsize += 16

    ## the WIM part number. For a single file this should be 1.
    checkbytes = checkfile.read(2)
    wimpartnumber = int.from_bytes(checkbytes, byteorder='little')
    if wimpartnumber != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot unpack multipart WIM'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## the total numbers of WIM parts
    checkbytes = checkfile.read(2)
    totalwimparts = int.from_bytes(checkbytes, byteorder='little')
    if totalwimparts != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot unpack multipart WIM'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## the image count
    checkbytes = checkfile.read(4)
    wimimagecount = int.from_bytes(checkbytes, byteorder='little')
    if wimimagecount != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'cannot unpack multipart WIM'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## the resources offset table are stored
    ## in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    reshdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    reshdrflags = reshdrflagssize >> 56

    ## lower 7 bytes are the size
    reshdrsize = reshdrflagssize & 72057594037927935
    unpackedsize += 8

    ## then the offset of the resource
    checkbytes = checkfile.read(8)
    resourceoffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + resourceoffset + reshdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    ## then the original size of the resource
    checkbytes = checkfile.read(8)
    resourceorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## the XML data is also stored in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    xmlhdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    xmlhdrflags = xmlhdrflagssize >> 56

    ## lower 7 bytes are the size
    xmlhdrsize = xmlhdrflagssize & 72057594037927935
    unpackedsize += 8

    ## then the offset of the xml
    checkbytes = checkfile.read(8)
    xmloffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + xmloffset + xmlhdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    ## then the original size of the XML
    checkbytes = checkfile.read(8)
    xmlorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## any boot information is also stored
    ## in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    boothdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    boothdrflags = boothdrflagssize >> 56

    ## lower 7 bytes are the size
    boothdrsize = boothdrflagssize & 72057594037927935
    unpackedsize += 8

    ## then the offset of the boot data
    checkbytes = checkfile.read(8)
    bootoffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + bootoffset + boothdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    ## then the original size of the boot data
    checkbytes = checkfile.read(8)
    bootorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## the boot index
    checkbytes = checkfile.read(4)
    bootindex = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## the integrity table is also stored
    ## in a reshdr_disk_short structure
    checkbytes = checkfile.read(8)
    integrityhdrflagssize = int.from_bytes(checkbytes, byteorder='little')
    integrityhdrflags = integrityhdrflagssize >> 56

    ## lower 7 bytes are the size
    integrityhdrsize = integrityhdrflagssize & 72057594037927935
    unpackedsize += 8

    ## then the offset of the boot data
    checkbytes = checkfile.read(8)
    integrityoffset = int.from_bytes(checkbytes, byteorder='little')
    if offset + integrityoffset + integrityhdrsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'resource outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    ## then the original size of the boot data
    checkbytes = checkfile.read(8)
    bootorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## record the maximum offset
    maxoffset = offset + max(unpackedsize, integrityoffset + integrityhdrsize, bootoffset + boothdrsize, xmloffset + xmlhdrsize, resourceoffset + reshdrsize)
    unpackedsize = maxoffset - offset

    ## extract and store the XML, as it might come in handy later
    wimxml = None
    if xmlhdrsize != 0:
        checkfile.seek(offset + xmloffset)
        checkbytes = checkfile.read(xmlhdrsize)
        try:
            wimxml = checkbytes.decode('utf_16_le')
        except:
            pass

    ## extra sanity check: parse the XML if any was extracted
    if wimxml != None:
        try:
            xml.dom.minidom.parseString(wimxml)
        except:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid XML stored in WIM'}
            return {'status': False, 'error': unpackingerror}

    if shutil.which('7z') == None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': '7z program not found'}
        return {'status': False, 'error': unpackingerror}

    havetmpfile = False
    if not (offset == 0 and filesize == unpackedsize):
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir, '-y', 'x', temporaryfile[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if offset == 0 and filesize == unpackedsize:
        checkfile.close()
        p = subprocess.Popen(['7z', '-o%s' % unpackdir, '-y', 'x', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid WIM file'}
        return {'status': False, 'error': unpackingerror}

    dirwalk = os.walk(unpackdir)
    for direntries in dirwalk:
        ## make sure all subdirectories and files can be accessed
        for subdir in direntries[1]:
            subdirname = os.path.join(direntries[0], subdir)
            if not os.path.islink(subdirname):
                os.chmod(subdirname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
        for filename in direntries[2]:
            fullfilename = os.path.join(direntries[0], filename)
            unpackedfilesandlabels.append((fullfilename, []))

    if not havetmpfile:
        labels.append('mswim')
        labels.append('compressed')
        labels.append('archive')

    ## cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://www.fileformat.info/format/sunraster/egff.htm
## This is not a perfect catch and Only some raster files
## might be labeled as such.
def unpackSunRaster(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## header has 8 fields, each 4 bytes
    if filesize - offset < 32:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip over the header
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## skip width
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    ## skip height
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    ## skip depth
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    ## length without header and colormap, can be 0
    checkbytes = checkfile.read(4)
    ras_length = int.from_bytes(checkbytes, byteorder='big')
    if ras_length == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'raster files with length 0 defined not supported'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## check type. Typical values are 0, 1, 2, 3, 4, 5 and 0xffff
    checkbytes = checkfile.read(4)
    ras_type = int.from_bytes(checkbytes, byteorder='big')
    if not ras_type in [0,1,2,3,4,5,0xffff]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unknown raster type field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    if ras_type != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'only standard type is supported'}
        return {'status': False, 'error': unpackingerror}

    ## check the color map type. Typical values are 0, 1, 2
    checkbytes = checkfile.read(4)
    ras_maptype = int.from_bytes(checkbytes, byteorder='big')
    if not ras_maptype in [0,1,2]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unknown color map type field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## length of colormap
    checkbytes = checkfile.read(4)
    ras_maplength = int.from_bytes(checkbytes, byteorder='big')

    ## check if the header + length of data
    ## + length of color map are inside the file
    if 32 + offset + ras_maplength + ras_length > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for raster file'}
        return {'status': False, 'error': unpackingerror}

    ## skip over the rest
    unpackedsize += 4 + ras_maplength + ras_length

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('sun raster')
        labels.append('raster')
        labels.append('binary')
        labels.append('graphics')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## Carve the image.
    ## first reset the file pointer
    checkfile.seek(offset)
    outfilename = os.path.join(unpackdir, "unpacked.rast")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['binary', 'sun raster', 'raster', 'graphics', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://en.wikipedia.org/wiki/Intel_HEX
## For now it is assumed that only files that are completely text
## files can be IHex files.
def unpackIHex(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    allowbroken = False

    ## open the file in text mode and process each line
    checkfile = open(filename, 'r')
    checkfile.seek(offset)

    outfilename = os.path.join(unpackdir, "unpacked-from-ihex")
    if filename.suffix.lower() == '.hex' or filename.suffix.lower() == '.ihex':
        outfilename = os.path.join(unpackdir, filename.stem)

    outfile = open(outfilename, 'wb')
    endofihex = False
    seenrecordtypes = set()

    ## process each line until the end of the IHex data is read
    try:
        for line in checkfile:
            if not line.startswith(':'):
                ## there could possibly be comments, starting with '#'
                if line.startswith('#'):
                    unpackedsize += len(line)
                    continue
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'line does not start with :'}
                return {'status': False, 'error': unpackingerror}
            ## minimum length for a line is:
            ## 1 + 2 + 4 + 2 + 2 = 11
            ## Each byte uses two characters. The start code
            ## uses 1 character.
            ## That means that each line has an uneven length.
            if len(line.strip()) < 11 or len(line.strip())%2 != 1:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough bytes in line'}
                return {'status': False, 'error': unpackingerror}

            bytescount = int.from_bytes(bytes.fromhex(line[1:3]), byteorder='big')
            if 3 + bytescount + 2 > len(line.strip()):
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough bytes in line'}
                return {'status': False, 'error': unpackingerror}

            ## the base address is from 3:7 and can be skipped
            ## the record type is next from 7:9
            recordtype = int.from_bytes(bytes.fromhex(line[7:9]), byteorder='big')
            if recordtype > 5:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'invalid record type'}
                return {'status': False, 'error': unpackingerror}

            computedchecksum = 0

            ## record type 0 is data, record type 1 is end of data
            ## Other record types do not include any data.
            if recordtype == 1:
                endofihex = True
            elif recordtype == 0:
                try:
                    ihexdata = bytes.fromhex(line[9:9+bytescount*2])
                except ValueError:
                    checkfile.close()
                    outfile.close()
                    os.unlink(outfilename)
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'cannot convert to hex'}
                    return {'status': False, 'error': unpackingerror}
                outfile.write(ihexdata)
            seenrecordtypes.add(recordtype)

            unpackedsize += len(line.strip()) + len(checkfile.newlines)

            if endofihex:
                break
    except UnicodeDecodeError:
        checkfile.close()
        outfile.close()
        os.unlink(outfilename)
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    outfile.close()

    if 4 in seenrecordtypes or 5 in seenrecordtypes:
        if 3 in seenrecordtypes:
            os.unlink(outfilename)
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'incompatible record types combined'}
            return {'status': False, 'error': unpackingerror}

    ## each valid IHex file has to have a terminator
    if not endofihex and not allowbroken:
        os.unlink(outfilename)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no end of data found'}
        return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfilename, []))
    if offset == 0 and filesize == unpackedsize:
        labels.append('text')
        labels.append('ihex')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://en.wikipedia.org/wiki/SREC_(file_format)
## For now it is assumed that only files that are completely text
## files can be SREC files.
def unpackSREC(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    allowbroken = False

    ## open the file in text mode and process each line
    checkfile = open(filename, 'r')
    checkfile.seek(offset)

    outfilename = os.path.join(unpackdir, "unpacked-from-srec")
    if filename.suffix.lower() == '.srec':
        outfilename = os.path.join(unpackdir, filename.stem)

    outfile = open(outfilename, 'wb')

    ## process each line until the end of the SREC data is read
    seenheader = False
    seenterminator = False
    seenrecords = set()
    try:
        for line in checkfile:
            ## keep track
            isdata = False
            if not line.startswith('S'):
                ## there could possibly be comments, starting with ';',
                ## although this is discouraged.
                if line.startswith(';'):
                    unpackedsize += len(line)
                    continue
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'line does not start with S'}
                return {'status': False, 'error': unpackingerror}

            ## minimum length for a line is:
            ## 2 + 2 + 4 + 2 = 10
            ## Each byte uses two characters. The record type uses
            ## two characters.
            ## That means that each line has an even length.
            if len(line.strip()) < 10 or len(line.strip())%2 != 0:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough bytes in line'}
                return {'status': False, 'error': unpackingerror}

            ## then the type. S0 is optional and has no data, S4 is
            ## reserved and S5 and S6 are not that interesting.
            if line[:2] == 'S1' or line[:2] == 'S2' or line[:2] == 'S3':
                isdata = True
            elif line[:2] == 'S7' or line[:2] == 'S8' or line[:2] == 'S9':
                seenterminator = True
            elif line[:2] == 'S4':
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'reserved S-Record value found'}
                return {'status': False, 'error': unpackingerror}
            else:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not an S-Record line'}
                return {'status': False, 'error': unpackingerror}
            recordtype = line[:2]
            seenrecords.add(recordtype)

            ## then the byte count
            try:
                bytescount = int.from_bytes(bytes.fromhex(line[2:4]), byteorder='big')
            except ValueError:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert to hex'}
                return {'status': False, 'error': unpackingerror}
            if bytescount < 3:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'bytecount too small'}
                return {'status': False, 'error': unpackingerror}
            if 4 + bytescount * 2 != len(line.strip()):
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough bytes in line'}
                return {'status': False, 'error': unpackingerror}

            ## skip the address field, or the count and read the data
            ## Depending on the record type the amount of bytes that
            ## the bytes count uses is different.
            try:
                if recordtype == 'S0':
                    ## metadata that should not be part of the file
                    srecdata = bytes.fromhex(line[8:8+(bytescount-3)*2])
                elif recordtype == 'S1':
                    srecdata = bytes.fromhex(line[8:8+(bytescount-3)*2])
                elif recordtype == 'S2':
                    srecdata = bytes.fromhex(line[10:10+(bytescount-4)*2])
                else:
                    srecdata = bytes.fromhex(line[12:12+(bytescount-5)*2])
            except ValueError:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert to hex'}
                return {'status': False, 'error': unpackingerror}

            ## write the unpacked data to a file, but only for the
            ## data records.
            if isdata:
                outfile.write(srecdata)
            unpackedsize += len(line.strip()) + len(checkfile.newlines)

            ## no need to continue if a terminator was found
            if seenterminator:
                break

    except UnicodeDecodeError:
        checkfile.close()
        outfile.close()
        os.unlink(outfilename)
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False, 'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    outfile.close()

    ## each valid SREC file has to have a terminator
    if not seenterminator and not allowbroken:
        os.unlink(outfilename)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no terminator record found'}
        return {'status': False, 'error': unpackingerror}

    ## sanity checks for the records:
    ## only certain combinations are allowed
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

    unpackedfilesandlabels.append((outfilename, []))
    if offset == 0 and filesize == unpackedsize:
        labels.append('text')
        labels.append('srec')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Unpacker for the ext2, ext3, ext4 file systems
## The file system is documented at:
##
## http://www.nongnu.org/ext2-doc/ext2.html
##
## The format is described in Chapter 3 and is used to implement
## several sanity checks. References to the specification point
## to this document. The heavy lifting is done using e2tools
## because it already takes care of deleted files, etc. through
## e2fsprogs-libs.
def unpackExt2(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## superblock starts at offset 1024 and is 1024 bytes (section 3.1)
    if filesize - offset < 2048:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for superblock'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('e2ls') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'e2ls program not found'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('e2cp') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'e2cp program not found'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip directly to the superblock
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+1024)
    unpackedsize += 1024

    ## Process the superblock and run many sanity checks.
    ## Extract the total number of inodes in the file system
    ## (section 3.1.1)
    checkbytes = checkfile.read(4)
    totalinodecount = int.from_bytes(checkbytes, byteorder='little')
    if totalinodecount == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'inodes cannot be 0'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## the total number of blocks in the file system (section 3.1.2)
    checkbytes = checkfile.read(4)
    totalblockcount = int.from_bytes(checkbytes, byteorder='little')
    if totalblockcount == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'block count cannot be 0'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## reserved block count for the superuser (section 3.1.3)
    checkbytes = checkfile.read(4)
    reservedblockcount = int.from_bytes(checkbytes, byteorder='little')
    if reservedblockcount > totalblockcount:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved blocks cannot exceed total blocks'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## free blocks in the system (section 3.1.4)
    checkbytes = checkfile.read(4)
    freeblockcount = int.from_bytes(checkbytes, byteorder='little')
    if freeblockcount > totalblockcount:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'free blocks cannot exceed total blocks'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## free inodes in the system (section 3.1.5)
    checkbytes = checkfile.read(4)
    freeinodes = int.from_bytes(checkbytes, byteorder='little')
    if freeinodes > totalinodecount:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'free inodes cannot exceed total inodes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## location of the first data block. Has to be 0 or 1. (section 3.1.6)
    checkbytes = checkfile.read(4)
    firstdatablock = int.from_bytes(checkbytes, byteorder='little')
    if firstdatablock != 0 and firstdatablock != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for first data block'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## the block size (section 3.1.7)
    checkbytes = checkfile.read(4)
    blocksize = 1024 << int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## check if the declared size is bigger than the file's size
    if offset + (totalblockcount * blocksize) > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'declared file system size larger than file size'}
        return {'status': False, 'error': unpackingerror}

    ## skip 4 bytes
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    ## determine the blocks per group (section 3.1.9)
    checkbytes = checkfile.read(4)
    blocks_per_group = int.from_bytes(checkbytes, byteorder='little')
    if blocks_per_group == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for blocks per group'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4
    blockgroups = math.ceil(totalblockcount/blocks_per_group)

    ## then skip a bunch of not so interesting values
    checkfile.seek(offset + 1024 + 76)
    unpackedsize = 1024+76

    ## check the revision level (section 3.1.23)
    checkbytes = checkfile.read(4)
    revision = int.from_bytes(checkbytes, byteorder='little')
    if not (revision == 0 or revision == 1):
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid ext2/3/4 revision'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## skip 8 bytes
    checkfile.seek(8, os.SEEK_CUR)
    unpackedsize += 8

    ## read the inode size, cannot be larger than
    ## block size (section 3.1.27)
    checkbytes = checkfile.read(2)
    inodesize = int.from_bytes(checkbytes, byteorder='little')
    if inodesize > blocksize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'inode size cannot be larger than block size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## skip 10 bytes
    checkfile.seek(10, os.SEEK_CUR)
    unpackedsize += 10

    ## read the RO compat flags (section 3.1.31)
    checkbytes = checkfile.read(4)
    rocompatflags = int.from_bytes(checkbytes, byteorder='little')
    if rocompatflags & 1 == 1:
        sparsesuperblocks = True
    else:
        sparsesuperblocks = False

    ## Now check for each block group if there is a copy of the
    ## superblock except if the sparse super block features is set
    ## (section 2.5).
    ## Find the right offset and then check if the magic byte is at
    ## that location, unless the block size is 1024, then it will be at
    ## the location + 1024.
    for i in range(1,blockgroups):
        ## super blocks are always present in block group 0 and 1, except
        ## if the block size = 1024
        ## Block group 0 contains the original superblock, which has
        ## already been processed.
        if not sparsesuperblocks:
            if blocksize == 1024:
                blockoffset = offset + i*blocksize*blocks_per_group+1024
            else:
                blockoffset = offset + i*blocksize*blocks_per_group
        else:
            ## if the sparse superblock feature is enabled
            ## the superblock can be found in each superblock
            ## that is a power of 3, 5 or 7
            sparsefound = False
            for p in [3,5,7]:
                if pow(p,int(math.log(i, p))) == i:
                    if blocksize == 1024:
                        blockoffset = offset + i*blocksize*blocks_per_group+1024
                    else:
                        blockoffset = offset + i*blocksize*blocks_per_group
                    sparsefound = True
                    break
            if not sparsefound:
                ## for anything that is not a power of 3, 5 or 7
                continue

        ## jump to the location of the magic header (section 3.1.16)
        ## and check its value. In a valid super block this value should
        ## always be the same.
        checkfile.seek(blockoffset + 0x38)
        checkbytes = checkfile.read(2)
        if not checkbytes == b'\x53\xef':
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid super block copy'}
            return {'status': False, 'error': unpackingerror}

    unpackedsize = totalblockcount * blocksize

    ## e2tools can work with trailing data, but if there is any data
    ## preceding the file system then some carving has to be done first.
    havetmpfile = False
    if not offset == 0:
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        havetmpfile = True
    checkfile.close()

    ## Now read the contents of the file system with e2ls and
    ## copy the files with e2cp.
    ## Unfortunately e2cp does not allow recursive copying, so the entire
    ## directory structure has to be walked recursively and recreated.
    ## Individual files have then to be copied with e2cp.
    ext2dirstoscan = collections.deque([''])

    ## store a mapping for inodes and files. This is needed to detect
    ## hard links, where files have the same inode.
    inodetofile = {}
    filetoinode = {}

    ## keep track of if any data was unpacked. Since file systems that
    ## have been created always have the "lost+found" directory it means
    ## that if no data could be unpacked it was not a valid file system,
    ## or at least it was not a useful file system.
    dataunpacked = False

    while True:
        try:
            ext2dir = ext2dirstoscan.popleft()
        except IndexError:
            ## there are no more entries to process
            break
        p = subprocess.Popen(['e2ls', '-lai', str(filename) + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'e2ls error'}
            return {'status': False, 'error': unpackingerror}
        dirlisting = outputmsg.rstrip().split(b'\n')
        for d in dirlisting:
            ## ignore deleted files
            if d.strip().startswith(b'>'):
                continue
            (inode, filemode, userid, groupid, size, filedate, filetime, ext2name) = re.split(b'\s+', d.strip(), 7)
            filemode = int(filemode, base=8)

            dataunpacked = True

            ## try to make sense of the filename by decoding it first.
            ## This might fail.
            namedecoded = False
            for c in encodingstotranslate:
               try:
                  ext2name = ext2name.decode()
                  namedecoded = True
                  break
               except Exception as e:
                  pass
            if not namedecoded:
               unpackingerror = {'offset': offset, 'fatal': False,
                                 'reason': 'could not decode file name'}
               return {'status': False, 'error': unpackingerror}

            ## Check the different file types
            if stat.S_ISDIR(filemode):
                ## It is a directory, so create it and then add
                ## it to the scanning queue, unless it is . or ..
                if ext2name == '.' or ext2name == '..':
                    continue
                newext2dir = os.path.join(ext2dir, ext2name)
                ext2dirstoscan.append(newext2dir)
                os.mkdir(os.path.join(unpackdir, newext2dir))
            elif stat.S_ISBLK(filemode):
                ## ignore block devices
                continue
            elif stat.S_ISCHR(filemode):
                ## ignore character devices
                continue
            elif stat.S_ISFIFO(filemode):
                ## ignore FIFO
                continue
            elif stat.S_ISSOCK(filemode):
                ## ignore sockets
                continue

            fullext2name = os.path.join(ext2dir, ext2name)
            filetoinode[fullext2name] = inode
            if stat.S_ISLNK(filemode):
                ## e2cp cannot copy symbolic links
                ## so just record it as a symbolic link
                ## TODO: process symbolic links
                pass
            elif stat.S_ISREG(filemode):
                if not inode in inodetofile:
                    inodetofile[inode] = fullext2name
                    ## use e2cp to copy the file
                    p = subprocess.Popen(['e2cp', str(filename) + ":" + fullext2name, "-d", os.path.join(unpackdir, ext2dir)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (outputmsg, errormsg) = p.communicate()
                    if p.returncode != 0:
                        unpackingerror = {'offset': offset, 'fatal': False,
                                          'reason': 'e2cp error'}
                        return {'status': False, 'error': unpackingerror}
                else:
                    ## hardlink the file to an existing
                    ## file and record it as such.
                    os.link(os.path.join(unpackdir, inodetofile[inode]), os.path.join(unpackdir, fullext2name))
                unpackedfilesandlabels.append((os.path.join(unpackdir,fullext2name), []))

    ## cleanup
    if havetmpfile:
        os.unlink(temporaryfile[1])

    ## only report if any data was unpacked
    if not dataunpacked:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no data unpacked'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and filesize == unpackedsize:
        labels.append('ext2')
        labels.append('file system')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## The RPM format is described as part of the Linux Standards Base:
##
## http://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/pkgformat.html
##
## There are references in the code to the right section in the LSB.
##
## This code can detect, but not unpack, delta RPMs:
##
## https://github.com/rpm-software-management/deltarpm/blob/master/README
def unpackRPM(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    ## the RPM lead is 96 bytes (section 22.2.1)
    if filesize - offset < 96:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 96 bytes'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0

    ## open the file and skip the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then process the RPM lead. Many of these values are duplicated
    ## in the header later in the file.

    ## read the major version. The standard version is 3. There have
    ## also been files with major 4.
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

    ## then read the type
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

    ## read the architecture
    checkbytes = checkfile.read(2)
    unpackedsize += 2

    ## the name of the file, should be NUL terminated
    checkbytes = checkfile.read(66)
    if not b'\x00' in checkbytes:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'name not NUL terminated'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 66

    ## osnum: "shall be 1"
    checkbytes = checkfile.read(2)
    osnum = int.from_bytes(checkbytes, byteorder='big')
    if osnum != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                         'fatal': False,
                         'reason': 'osnum not 1'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## signature type: "shall be 5"
    checkbytes = checkfile.read(2)
    signaturetype = int.from_bytes(checkbytes, byteorder='big')
    if signaturetype != 5:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'signature type not 5'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## skip over the 'reserved space'
    checkfile.seek(16, os.SEEK_CUR)
    unpackedsize += 16

    ## signature, in header format (section 22.2.2 and 22.2.3)
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

    ## reserved space
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

    ## number of index records, should be at least 1
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

    ## the size of the storage area for the data pointed to by
    ## the index records
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for index record size'}
        return {'status': False, 'error': unpackingerror}
    signaturehsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## process all the index records (section 22.2.2.2)
    for i in range(0,signatureindexrecordcount):
        ## first the tag
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record tag'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then the type
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record type'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        ## then the offset
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

        ## the size of the record
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index count'}
            return {'status': False, 'error': unpackingerror}
        indexcount = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

    ## then the signature size
    if checkfile.tell() + signaturehsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                         'reason': 'not enough data for signature storage area'}
        return {'status': False, 'error': unpackingerror}

    checkfile.seek(signaturehsize, os.SEEK_CUR)
    unpackedsize += signaturehsize

    ## then pad on an 8 byte boundary
    if unpackedsize%8 != 0:
        checkfile.seek(8 - unpackedsize%8, os.SEEK_CUR)
        unpackedsize += 8 - unpackedsize%8

    ## Next is the Header, which is identical to the Signature
    ## (section 22.2.2 and 22.2.3)
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

    ## reserved space
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

    ## number of index records, should be at least 1
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

    ## the size of the storage area for the data pointed
    ## to by the index records
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for index record size'}
        return {'status': False, 'error': unpackingerror}
    headerhsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    ## keep a list of tags to offsets and sizes
    headertagtooffsets = {}

    ## process all the index records (section 22.2.2.2)
    for i in range(0,headerindexrecordcount):
        ## first the tag
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record tag'}
            return {'status': False, 'error': unpackingerror}
        headertag = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        ## then the type
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index record type'}
            return {'status': False, 'error': unpackingerror}
        headertype = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        ## then the offset
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

        ## the size of the record
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for index count'}
            return {'status': False, 'error': unpackingerror}
        indexcount = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        if not headertag in headertagtooffsets:
            headertagtooffsets[headertag] = (indexoffset, indexcount, headertype)

    ## then the header size
    if checkfile.tell() + headerhsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header storage area'}
        return {'status': False, 'error': unpackingerror}

    ## first store the old offset
    oldoffset = checkfile.tell()

    tagstoresults = {}

    ## and inspect each of the tags, which are not necessarily ordered
    for i in headertagtooffsets:
        checkfile.seek(oldoffset)
        (tagoffset, tagcount, tagtype) = headertagtooffsets[i]
        checkfile.seek(tagoffset, os.SEEK_CUR)

        ## store results for tags, for now for strings only
        tagresults = []

        ## depending on the type a different size has to be read
        ## (section 22.2.2.2.1)
        for c in range(0,tagcount):
            ## char
            if tagtype == 1:
                checkbytes = checkfile.read(1)
            ## int8
            elif tagtype == 2:
                checkbytes = checkfile.read(1)
            ## int16
            elif tagtype == 3:
                ## TODO: alignment
                checkbytes = checkfile.read(2)
            ## int32
            elif tagtype == 4:
                ## TODO: alignment
                checkbytes = checkfile.read(4)
            ## reserved
            elif tagtype == 5:
                pass
            ## string
            elif tagtype == 6:
                tagstr = b''
                while True:
                    checkbytes = checkfile.read(1)
                    if checkbytes == b'\x00':
                        break
                    tagstr += checkbytes
                tagresults.append(tagstr)
            ## bin
            elif tagtype == 7:
                checkbytes = checkfile.read(1)
                pass
            ## string array
            elif tagtype == 8:
                tagstr = b''
                while True:
                    checkbytes = checkfile.read(1)
                    if checkbytes == b'\x00':
                        break
                    tagstr += checkbytes
                tagresults.append(tagstr)
            ## i18n type
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

    ## then seek back to the old offset
    checkfile.seek(oldoffset)

    ## then jump over the header data
    checkfile.seek(headerhsize, os.SEEK_CUR)
    unpackedsize += signaturehsize

    ## then unpack the file. This depends on the compressor and the
    ## payload format.  The default compressor is either gzip or XZ
    ## (on Fedora). Other supported compressors are bzip2, LZMA and
    ## zstd (recent addition).
    ##
    ## 1125 is the tag for the compressor.
    if not 1125 in tagstoresults:
        ## gzip by default
        unpackresult = unpackGzip(filename, checkfile.tell(), unpackdir, temporarydirectory)
    else:
        if len(tagstoresults[1125]) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'duplicate compressor defined'}
            return {'status': False, 'error': unpackingerror}
        compressor = tagstoresults[1125][0]
        if compressor == b'gzip':
            unpackresult = unpackGzip(filename, checkfile.tell(), unpackdir, temporarydirectory)
        elif compressor == b'bzip2':
            unpackresult = unpackBzip2(filename, checkfile.tell(), unpackdir, temporarydirectory)
        elif compressor == b'xz':
            unpackresult = unpackXZ(filename, checkfile.tell(), unpackdir, temporarydirectory)
        elif compressor == b'lzma':
            unpackresult = unpackLZMA(filename, checkfile.tell(), unpackdir, temporarydirectory)
        elif compressor == b'zstd':
            unpackresult = unpackZstd(filename, checkfile.tell(), unpackdir, temporarydirectory)
        else:
            ## gzip is default
            unpackresult = unpackGzip(filename, checkfile.tell(), unpackdir, temporarydirectory)

    if not unpackresult['status']:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'could not decompress payload'}
        return {'status': False, 'error': unpackingerror}

    rpmunpacksize = unpackresult['length']
    rpmunpackfiles = unpackresult['filesandlabels']
    if len(rpmunpackfiles) != 1:
        ## this should never happen
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'could not decompress payload'}
        return {'status': False, 'error': unpackingerror}

    payload = None
    payloadfile = rpmunpackfiles[0][0]

    ## 1124 is the payload. Only 'cpio' can be unpacked at the moment.
    if 1124 in tagstoresults:
        if len(tagstoresults[1124]) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'duplicate payload defined'}
            return {'status': False, 'error': unpackingerror}

        payload = tagstoresults[1124][0]
        if payload == b'cpio':
            ## first move the payload file to a different location
            ## to avoid any potential name clashes
            payloaddir = pathlib.Path(tempfile.mkdtemp(dir=temporarydirectory))
            shutil.move(payloadfile, payloaddir)
            unpackresult = unpackCpio(payloaddir / os.path.basename(payloadfile), 0, unpackdir, temporarydirectory)
            ## cleanup
            shutil.rmtree(payloaddir)
            if not unpackresult['status']:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'could not unpack CPIO payload'}
                return {'status': False, 'error': unpackingerror}
            for i in unpackresult['filesandlabels']:
                    unpackedfilesandlabels.append((os.path.normpath(i[0]), i[1]))
        elif payload == b'drpm':
            unpackedfilesandlabels.append((payloadfile, ['delta rpm data']))

    unpackedsize = checkfile.tell() + rpmunpacksize - offset

    if offset == 0 and unpackedsize == filesize:
        labels.append('rpm')
        if issourcerpm:
            labels.append('srpm')
            labels.append('source rpm')
        if payload == b'drpm':
            labels.append('delta rpm')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## zstd
## https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
def unpackZstd(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    if shutil.which('zstd') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'zstd program not found'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    ## skip the magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then read the frame header descriptor as it might indicate
    ## whether or not there is a size field.
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

    ## process the frame header descriptor to see how big the
    ## frame header is.
    frame_content_size_flag = ord(checkbytes) >> 6
    if frame_content_size_flag == 3:
        fcs_field_size = 8
    elif frame_content_size_flag == 2:
        fcs_field_size = 4
    elif frame_content_size_flag == 1:
        fcs_field_size = 2
    else:
        ## now it depends on the single_segment_flag
        if not single_segment:
            fcs_field_size = 0
        else:
            fcs_field_size = 1

    ## reserved bit MUST 0
    if ord(checkbytes) & 8 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved bit set'}
        return {'status': False, 'error': unpackingerror}

    ## content checksum flag
    content_checksum_set = False
    if ord(checkbytes) & 4 == 4:
        content_checksum_set = True

    ## then did_field_size
    if ord(checkbytes) & 3 == 0:
        did_field_size = 0
    elif ord(checkbytes) & 3 == 1:
        did_field_size = 1
    elif ord(checkbytes) & 3 == 2:
        did_field_size = 2
    elif ord(checkbytes) & 3 == 3:
        did_field_size = 4

    ## check to see if the window descriptor is present
    if not single_segment:
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for window descriptor'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    ## then read the dictionary
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

    ## then the blocks: each block starts with 3 bytes
    while True:
        lastblock = False
        checkbytes = checkfile.read(3)
        if len(checkbytes) != 3:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for frame'}
            return {'status': False, 'error': unpackingerror}
        ## first check if it is the last block
        if checkbytes[0] & 1 == 1:
            lastblock = True
        blocksize = int.from_bytes(checkbytes, byteorder='little') >> 3
        if checkfile.tell() + blocksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for frame'}
            return {'status': False, 'error': unpackingerror}
        checkfile.seek(blocksize, os.SEEK_CUR)
        if lastblock:
            break

    if content_checksum_set:
        ## lower 32 bytes of xxHash checksum of the original
        ## decompressed data
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for checksum'}
            return {'status': False, 'error': unpackingerror}

    unpackedsize = checkfile.tell() - offset

    ## zstd does not record the name of the file that was
    ## compressed, so guess, or just set a name.
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        if filename.suffix.lower() == '.zst':
            outfilename = os.path.join(unpackdir, filename.stem)
        else:
            outfilename = os.path.join(unpackdir, "unpacked-by-zstd")
        p = subprocess.Popen(['zstd', '-d', '-o', outfilename, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid zstd'}
            return {'status': False, 'error': unpackingerror}
        if fcs_field_size != 0:
            if uncompressed_size != os.stat(outfilename).st_size:
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid checksum'}
                return {'status': False, 'error': unpackingerror}
        labels.append('zstd')
        labels.append('compressed')
    else:
        tmpfilename = os.path.join(unpackdir, "unpacked-by-zstd.zst")
        tmpfile = open(tmpfilename, 'wb')
        os.sendfile(tmpfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        tmpfile.close()
        checkfile.close()
        outfilename = tmpfilename[:-4]
        p = subprocess.Popen(['zstd', '-d', '--rm', '-o', outfilename, tmpfilename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            os.unlink(tmpfilename)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid zstd'}
            return {'status': False, 'error': unpackingerror}
        if fcs_field_size != 0:
            if uncompressed_size != os.stat(outfilename).st_size:
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid checksum'}
                return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfilename, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://en.wikipedia.org/wiki/Apple_Icon_Image_format
def unpackAppleIcon(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    checkfile = open(filename, 'rb')
    ## skip over the magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## file length is next
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for icon length'}
        return {'status': False, 'error': unpackingerror}
    appleiconlength = int.from_bytes(checkbytes, byteorder='big')

    ## data cannot be outside of file
    if appleiconlength + offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'icon cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## then the actual icon data
    while unpackedsize < appleiconlength:
        ## first the icon type
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough icon data for icon type'}
            return {'status': False, 'error': unpackingerror}
        icontype = checkbytes
        unpackedsize += 4

        ## then the icon data length (including type and length)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough icon data'}
            return {'status': False, 'error': unpackingerror}
        iconlength = int.from_bytes(checkbytes, byteorder='big')
        ## icon length cannot be outside of the file. The length field
        ## includes the type and length, and unpackedsize already has
        ## 4 bytes of the type added, so subtract 4 in the check.
        if offset + unpackedsize - 4 + iconlength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'icon data outside of file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        checkfile.seek(iconlength-8, os.SEEK_CUR)
        unpackedsize += iconlength-8

    if offset == 0 and unpackedsize == filesize:
        ## now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid Apple icon according to PIL'}
            return {'status': False, 'error': unpackingerror}
        checkfile.close()

        labels.append('apple icon')
        labels.append('graphics')
        labels.append('resource')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## Carve the image.
    ## first reset the file pointer
    checkfile.seek(offset)
    outfilename = os.path.join(unpackdir, "unpacked.icns")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    ## reopen as read only
    outfile = open(outfilename, 'rb')

    ## now load the file into PIL as an extra sanity check
    try:
        testimg = PIL.Image.open(outfile)
        testimg.load()
        testimg.close()
        outfile.close()
    except:
        outfile.close()
        os.unlink(outfilename)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid Apple icon according to PIL'}
        return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfilename, ['apple icon', 'graphics', 'resource', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## MNG specifications can be found at:
##
## http://www.libpng.org/pub/mng/spec/
## https://en.wikipedia.org/wiki/Multiple-image_Network_Graphics
##
## This format is almost never used and support for it in
## programs is spotty.
def unpackMNG(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    if filesize - offset < 52:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 52 bytes'}
        return {'status': False, 'error': unpackingerror}

    ## open the file skip over the magic header bytes
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+8)
    unpackedsize = 8

    ## Then process the MNG data. All data is in network byte order
    ## (section 1). First read the size of the first chunk, which is
    ## always 28 bytes (section 4.1.1).
    ## Including the header, chunk type and CRC 40 bytes have to be read
    checkbytes = checkfile.read(40)
    if checkbytes[0:4] != b'\x00\x00\x00\x1c':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'no valid chunk length'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}

    ## The first chunk *has* to be MHDR
    if checkbytes[4:8] != b'MHDR':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'no MHDR header'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}

    ## then compute the CRC32 of bytes 4 - 24 (header + data)
    ## and compare it to the CRC in the MNG file
    crccomputed = binascii.crc32(checkbytes[4:-4])
    crcstored = int.from_bytes(checkbytes[-4:], byteorder='big')
    if crccomputed != crcstored:
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                          'reason': 'Wrong CRC'}
        checkfile.close()
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 40

    ## Then move on to the next chunks in similar fashion
    endoffilereached = False
    chunknames = set()

    while True:
        ## read the chunk size
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

        ## read the chunk type, plus the chunk data
        checkbytes = checkfile.read(4+chunksize)
        chunktype = checkbytes[0:4]
        if len(checkbytes) != 4+chunksize:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False,
                              'reason': 'Could not read chunk type'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}

        unpackedsize += 4+chunksize

        ## compute the CRC
        crccomputed = binascii.crc32(checkbytes)
        checkbytes = checkfile.read(4)
        crcstored = int.from_bytes(checkbytes, byteorder='big')
        if crccomputed != crcstored:
            unpackingerror = {'offset': offset + unpackedsize,
                              'fatal': False, 'reason': 'Wrong CRC'}
            checkfile.close()
            return {'status': False, 'error': unpackingerror}

        ## add the name of the chunk to the list of chunk names
        chunknames.add(chunktype)
        if chunktype == b'MEND':
            ## MEND indicates the end of the file
            endoffilereached = True
            unpackedsize += 4
            break
        unpackedsize += 4

    ## There has to be exactly 1 MEND chunk
    if endoffilereached:
        if offset == 0 and unpackedsize == filesize:
            checkfile.close()
            labels += ['mng', 'graphics']
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        ## else carve the file. It is anonymous, so just give it a name
        outfilename = os.path.join(unpackdir, "unpacked.mng")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()

        unpackedfilesandlabels.append((outfilename, ['mng', 'graphics', 'unpacked']))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## There is no end of file, so it is not a valid MNG.
    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'No MEND found'}
    return {'status': False, 'error': unpackingerror}

## The Android sparse format is documented in the Android source code tree:
##
## https://android.googlesource.com/platform/system/core/+/master/libsparse/sparse_format.h
##
## Tool to create images with for testing:
##
## * https://android.googlesource.com/platform/system/core/+/master/libsparse - img2simg.c
##
## Note: this is different to the Android sparse data image format.
def unpackAndroidSparse(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    unpackedsize = 0
    checkfile = open(filename, 'rb')

    if filesize - offset < 28:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not enough bytes'}
        return {'status': False, 'error': unpackingerror}

    ## first skip over the magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then read the major version
    checkbytes = checkfile.read(2)
    ## only version 1 is supported according to the header file from Android
    major_version = int.from_bytes(checkbytes, byteorder='little')
    if major_version != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong major version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## skip over the minor version
    checkfile.seek(2,os.SEEK_CUR)
    unpackedsize += 2

    ## then read the file header size (should be 28)
    checkbytes = checkfile.read(2)
    file_hdr_sz = int.from_bytes(checkbytes, byteorder='little')
    if file_hdr_sz != 28:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong file header size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## then the chunk header size (should be 12)
    checkbytes = checkfile.read(2)
    chunk_hdr_sz = int.from_bytes(checkbytes, byteorder='little')
    if chunk_hdr_sz != 12:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong chunk header size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## then the block size, must be a multiple of 4
    checkbytes = checkfile.read(4)
    blk_sz = int.from_bytes(checkbytes, byteorder='little')
    if blk_sz % 4 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong block size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## the total number of blocks in the uncompressed image
    checkbytes = checkfile.read(4)
    total_blks = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## the total number of chunks in the compressed image
    checkbytes = checkfile.read(4)
    total_chunks = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## then skip over the checksum and look at the individual chunks
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## definitions for the different types of chunks
    ## swap with the definitions in the header file from Android
    ## because of endianness.
    CHUNK_TYPE_RAW = b'\xc1\xca'
    CHUNK_TYPE_FILL     = b'\xc2\xca'
    CHUNK_TYPE_DONT_CARE = b'\xc3\xca'
    CHUNK_TYPE_CRC32 = b'\xc4\xca'

    ## open an output file
    outputfilename = os.path.join(unpackdir, "sparse.out")
    outputfile = open(outputfilename, 'wb')

    ## then determine the size of the sparse file
    for i in range(0,total_chunks):
        ## each chunk has a 12 byte header
        checkbytes = checkfile.read(12)
        if len(checkbytes) != 12:
            checkfile.close()
            outputfile.close()
            os.unlink(outputfilename)
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'Not a valid Android sparse file: not enough bytes in chunk header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 12

        chunk_sz = int.from_bytes(checkbytes[4:8], byteorder='little')
        total_sz = int.from_bytes(checkbytes[8:], byteorder='little')
        if checkbytes[0:2] == CHUNK_TYPE_RAW:
            if chunk_sz * blk_sz + offset + unpackedsize > filesize:
                checkfile.close()
                outputfile.close()
                os.unlink(outputfilename)
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'Not a valid Android sparse file: not enough data'}
                return {'status': False, 'error': unpackingerror}
            for c in range(0, chunk_sz):
                outputfile.write(checkfile.read(blk_sz))
            unpackedsize += chunk_sz * blk_sz
        elif checkbytes[0:2] == CHUNK_TYPE_FILL:
            ## the next 4 bytes are the fill data
            filldata = checkfile.read(4)
            for c in range(0, chunk_sz):
                ## It has already been checked that blk_sz
                ## is divisible by 4.
                outputfile.write(filldata*(blk_sz//4))
            unpackedsize += 4
        elif checkbytes[0:2] == CHUNK_TYPE_DONT_CARE:
            ## just fill the next X blocks with '\x00'
            for c in range(0, chunk_sz):
                outputfile.write(b'\x00' * blk_sz)
            unpackedsize += 0
        elif checkbytes[0:2] == CHUNK_TYPE_CRC32:
            ## no idea what to do with this at the moment
            ## so just skip over it.
            checkfile.seek(4,os.SEEK_CUR)
            unpackedsize += 4
        else:
            checkfile.close()
            outputfile.close()
            os.unlink(outputfilename)
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'Not a valid Android sparse file: unknown chunk'}
            return {'status': False, 'error': unpackingerror}

    outputfile.close()
    checkfile.close()
    if offset == 0 and filesize == unpackedsize:
        labels.append('androidsparse')
    unpackedfilesandlabels.append((outputfilename, []))
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'Not a valid Android sparse file'}
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## https://github.com/lz4/lz4/blob/master/doc/lz4_Frame_format.md
## uses https://pypi.org/project/lz4/
def unpackLZ4(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    outfilename = os.path.join(unpackdir, "unpacked-from-lz4")
    outfile = open(outfilename, 'wb')

    ## first create a decompressor object
    decompressor = lz4.frame.create_decompression_context()

    checkfile = open(filename, 'rb')
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
            os.unlink(outfilename)
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'LZ4 unpacking error'}
            return {'status': False, 'error': unpackingerror}

        unpackedsize += uncompressresults[1]

        ## end of the data/LZ4 frame footer
        if uncompressresults[2]:
            outfile.close()
            seeneof = True
            break
        checkbytes = checkfile.read(readsize)

    outfile.close()
    checkfile.close()

    if not seeneof:
        os.unlink(outfilename)
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data incomplete'}
        return {'status': False, 'error': unpackingerror}

    ## in case the whole file name is the lz4 file and the extension
    ## is .lz4 rename the file.
    if offset == 0 and unpackedsize == filesize:
        labels.append('compressed')
        labels.append('lz4')
        if filename.suffix.lower() == '.lz4':
            newoutfilename = os.path.join(unpackdir, filename.stem)
            shutil.move(outfilename, newoutfilename)
            outfilename = newoutfilename
    unpackedfilesandlabels.append((outfilename, []))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## VMware VMDK files
##
## The website:
##
## https://www.vmware.com/app/vmdk/?src=vmdk
##
## has a PDF of specification, but these are a bit outdated
##
## Newer specs:
##
## https://www.vmware.com/support/developer/vddk/vmdk_50_technote.pdf
##
## https://github.com/libyal/libvmdk/blob/master/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc
## in section 4
##
## For now just focus on files where the entire file is VMDK
def unpackVMDK(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    if filesize - offset < 512:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 512 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('qemu-img') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'qemu-img program not found'}
        return {'status': False, 'error': unpackingerror}

    ## first run qemu-img in case the whole file is the VMDK file
    if offset == 0:
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', filename],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            ## extra sanity check to see if it is valid JSON
            try:
               vmdkjson = json.loads(standardout)
            except:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'no valid JSON output from qemu-img'}
                return {'status': False, 'error': unpackingerror}
            if filename.suffix.lower() == '.vmdk':
                outputfilename = os.path.join(unpackdir, filename.stem)
            else:
                outputfilename = os.path.join(unpackdir, 'unpacked-from-vmdk')

            ## now convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', filename, outputfilename],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                if os.path.exists(outputfilename):
                    os.unlink(outputfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert file'}
                return {'status': False, 'error': unpackingerror}

            labels.append('vmdk')
            labels.append('file system')
            unpackedfilesandlabels.append((outputfilename, []))
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'Not a valid VMDK file or cannot unpack'}
    return {'status': False, 'error': unpackingerror}

## QEMU qcow2 files
##
## Specification can be found in docs/interop in the QEMU repository
##
## https://git.qemu.org/?p=qemu.git;a=blob;f=docs/interop/qcow2.txt;hb=HEAD
def unpackQcow2(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}

    if filesize - offset < 72:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'File too small (less than 72 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('qemu-img') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'qemu-img program not found'}
        return {'status': False, 'error': unpackingerror}

    ## first run qemu-img in case the whole file is the qcow2 file
    if offset == 0:
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', filename],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            ## extra sanity check to see if it is valid JSON
            try:
               vmdkjson = json.loads(standardout)
            except:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'no valid JSON output from qemu-img'}
                return {'status': False, 'error': unpackingerror}
            if filename.suffix.lower() == '.qcow2':
                outputfilename = os.path.join(unpackdir, filename.stem)
            else:
                outputfilename = os.path.join(unpackdir, 'unpacked-from-qcow2')

            ## now convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', filename, outputfilename],
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                if os.path.exists(outputfilename):
                    os.unlink(outputfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert file'}
                return {'status': False, 'error': unpackingerror}

            labels.append('qemu')
            labels.append('qcow2')
            labels.append('file system')
            unpackedfilesandlabels.append((outputfilename, []))
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                      'reason': 'Not a valid qcow2 file or cannot unpack'}
    return {'status': False, 'error': unpackingerror}

## VirtualBox VDI
##
## https://forums.virtualbox.org/viewtopic.php?t=8046
def unpackVDI(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}

    if filesize - offset < 512:
        unpackingerror = {'offset': offset,
                          'fatal': False,
                          'reason': 'File too small (less than 512 bytes'}
        return {'status': False, 'error': unpackingerror}

    if shutil.which('qemu-img') == None:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'qemu-img program not found'}
        return {'status': False, 'error': unpackingerror}

    ## open the file skip over the magic header bytes
    checkfile = open(filename, 'rb')

    ## This assumes the Oracle flavour of VDI. There have been
    ## others in the past.
    checkfile.seek(offset+40)
    unpackedsize = 40

    ## 24 NUL bytes
    checkbytes = checkfile.read(24)
    if checkbytes != b'\x00' * 24:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for padding bytes'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 24

    ## then the image signature
    checkbytes = checkfile.read(4)
    if checkbytes != b'\x7f\x10\xda\xbe':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for image signature'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## major version
    checkbytes = checkfile.read(2)
    majorversion = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## minor version
    checkbytes = checkfile.read(2)
    minorversion = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## size of header, should be 0x190
    checkbytes = checkfile.read(4)
    headersize = int.from_bytes(checkbytes, byteorder='little')
    if headersize != 0x190:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for header size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## image type
    checkbytes = checkfile.read(4)
    imagetype = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## image flags
    checkbytes = checkfile.read(4)
    imageflags = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## image description, unclear how big it is
    #checkbytes = checkfile.read(32)
    #unpackedsize += 32

    ## skip to 0x154
    checkfile.seek(offset + 0x154)
    unpackedsize = 0x154

    ## offset blocks
    checkbytes = checkfile.read(4)
    offsetblocks = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## offset data
    checkbytes = checkfile.read(4)
    offsetdata = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## cylinders
    checkbytes = checkfile.read(4)
    cylinders = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## heads
    checkbytes = checkfile.read(4)
    heads = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## sectors
    checkbytes = checkfile.read(4)
    sectors = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## sector size (should be 512)
    checkbytes = checkfile.read(4)
    sectorsize = int.from_bytes(checkbytes, byteorder='little')
    if sectorsize != 512:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for sector size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## skip unused bytes
    checkfile.seek(4, os.SEEK_CUR)

    ## disk size (uncompressed)
    checkbytes = checkfile.read(8)
    disksize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## block size
    checkbytes = checkfile.read(4)
    blocksize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## block extra data
    checkbytes = checkfile.read(4)
    blockextradata = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## blocks in hdd
    checkbytes = checkfile.read(4)
    blocksinhdd = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## blocks allocated
    checkbytes = checkfile.read(4)
    blocksallocated = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## now there is enough information to do some sanity checks
    ## First see if the file is large enough
    if offset + (2+blocksallocated) * blocksize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'data cannot be outside of file'}
        return {'status': False, 'error': unpackingerror}

    ## check to see if the VDI is the entire file. If so unpack it.
    if offset == 0 and (2+blocksallocated) * blocksize == filesize:
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', filename],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            ## extra sanity check to see if it is valid JSON
            try:
               vmdkjson = json.loads(standardout)
            except:
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no valid JSON output from qemu-img'}
                return {'status': False, 'error': unpackingerror}
            if filename.suffix.lower() == '.vdi':
                outputfilename = os.path.join(unpackdir, filename.stem)
            else:
                outputfilename = os.path.join(unpackdir, 'unpacked-from-vdi')

            ## now convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', filename, outputfilename],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                if os.path.exists(outputfilename):
                    os.unlink(outputfilename)
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'cannot convert file'}
                return {'status': False, 'error': unpackingerror}

            labels.append('virtualbox')
            labels.append('vdi')
            labels.append('file system')
            unpackedfilesandlabels.append((outputfilename, []))
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    ## TODO: snapshots and carving

    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                     'reason': 'Not a valid VDI file or cannot unpack'}
    return {'status': False, 'error': unpackingerror}

## XML specification: https://www.w3.org/TR/2008/REC-xml-20081126/
def unpackXML(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    if shutil.which('xmllint') == None:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'xmllint program not found'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': oldoffset, 'fatal': False,
                          'reason': 'not enough data'}

    ## XML files sometimes start with a Byte Order Mark
    ## https://en.wikipedia.org/wiki/Byte_order_mark
    ## XML specification, section F.1
    if checkbytes[0:3] == b'\xef\xbb\xbf':
        unpackedsize += 3
        ## rewind one byte, as only three bytes were consumed
        checkfile.seek(-1, os.SEEK_CUR)
    else:
        ## else reset to the beginning
        checkfile.seek(offset)

    ## White space is defined in the XML specification (section 2.3)
    ## and can appear before the processing instruction (see section 2.4)
    ## A document has to start with a processing instruction (section 2.6)
    while True:
        checkbytes = checkfile.read(1)
        if checkbytes == b'':
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid character at start of XML file'}
            return {'status': False, 'error': unpackingerror}
        if not checkbytes in [b' ', b'\n', b'\r', b'\t', b'<']:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid character at start of XML file'}
            return {'status': False, 'error': unpackingerror}

        ## check to see if the start of the XML data is found. If not,
        ## it's white space, so read another character to see if there
        ## is more whitespace.
        if checkbytes == b'<':
            ## a processing instruction (section 2.6) might follow.
            ## The first one should start with "<?xml" (case insensitive)
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough data for XML'}
                return {'status': False, 'error': unpackingerror}
            if checkbytes.lower() != b'?xml':
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid processing instruction at start of file'}
                return {'status': False, 'error': unpackingerror}
            break

    checkfile.close()

    ## now run xmllint as a sanity check. By default xmllint tries to
    ## resolve external entities, so this should be prevented by
    ## supplying "--nonet"
    p = subprocess.Popen(['xmllint','--noout', "--nonet", filename],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'xmllint cannot parse file'}
        return {'status': False, 'error': unpackingerror}

    ## whole file is XML
    labels.append('xml')
    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

## Uses the description of the Java class file format as described here:
##
## https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html
## TODO: many more checks for valid pointers into the constant pool
def unpackJavaClass(filename, offset, unpackdir, temporarydirectory):
    ## a couple of constants. Same names as in the Java class
    ## documentation from Oracle.
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

    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## The minimal size for a valid Java class file is 24 bytes: magic
    ## (4 bytes) plus 2 bytes for minor_version, major_version,
    ## constant_pool_count access_flags, this_class, super_class,
    ## interfaces_count, fields_count, methods_count and attributes_count
    if filesize - offset < 24:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough bytes'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')

    ## skip over the magic header
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then skip 4 bytes (major + minor versions)
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4

    ## Then read two bytes (constant pool count)
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

    ## a mapping of classes to corresponding entries in the constant
    ## pool section 4.4.1
    class_table = {}

    ## read the constants. Many of these have pointers back into the
    ## constant_pool for names (methods, signatures, etc.).
    for i in range(1,constant_pool_count):
        if islongordouble:
            islongordouble = False
            continue
        ## first read one byte, which is the constant "tag",
        ## section 4.4 of specification
        tagbyte = checkfile.read(1)
        if len(tagbyte) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no constant pool tag'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
        tag = ord(tagbyte)
        ## how much data is then stored per constant type depends
        ## on the type
        if tag == CONSTANT_Class:
            ## section 4.4.1
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no name_index'}
                return {'status': False, 'error': unpackingerror}
            class_table[i] = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 2
        elif tag == CONSTANT_Fieldref or tag == CONSTANT_Methodref or tag == CONSTANT_InterfaceMethodref:
            ## section 4.4.2
            ## class index
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no class_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            class_index = int.from_bytes(checkbytes, byteorder='big')

            ## name and type index
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
            ## section 4.4.3
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no string_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
        elif tag == CONSTANT_Integer or tag == CONSTANT_Float:
            ## section 4.4.4
            checkbytes = checkfile.read(4)
            if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no integer/float bytes'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 4
        elif tag == CONSTANT_Long or tag == CONSTANT_Double:
            ## section 4.4.5
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
            ## longs and doubles take two entries in the constant pool
            ## so one entry needs to be skipped according to section 4.4.5
            islongordouble = True
        elif tag == CONSTANT_NameAndType:
            ## section 4.4.6
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
            ## section 4.4.7
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
            ## Caveat: Java uses its own "modified UTF-8", as described
            ## in 4.4.7. Assume for now that only simple ASCII is being
            ## used. This is a mistake.
            try:
                constant_pool[i] = utf8bytes.decode()
            except:
                constant_pool[i] = utf8bytes
            if len(utf8bytes) != utf8len:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough utf8 bytes (%d needed)' % utf8len}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += utf8len
        elif tag == CONSTANT_MethodHandle:
            ## section 4.4.8
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
            ## section 4.4.9
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no descriptor_index'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
        elif tag == CONSTANT_InvokeDynamic:
            ## section 4.4.10
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
    ## end of the constant pool reached

    ## sanity check: verify all the class objects have valid pointers
    ## to valid indexes in the constant pool
    for c in class_table:
        if not class_table[c] in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'class info object does not have valid pointer into constant pool'}
            return {'status': False, 'error': unpackingerror}

    ## read the access flags
    access_flags = checkfile.read(2)
    if len(access_flags) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no access_flags'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## this_class
    ## This points to an index in the constant pool table, which should
    ## be a class file (which here are kept in class_table instead).
    this_class = checkfile.read(2)
    if len(this_class) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no this_class'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    this_class_index = int.from_bytes(this_class, byteorder='big')
    if not this_class_index in class_table:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no valid pointer into class table'}
        return {'status': False, 'error': unpackingerror}

    ## super_class
    super_class = checkfile.read(2)
    if len(super_class) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no super_class'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## interfaces_count
    interfaces_count_bytes = checkfile.read(2)
    if len(interfaces_count_bytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no interfaces_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    interfaces_count = int.from_bytes(interfaces_count_bytes, byteorder='big')

    ## read the interfaces
    for i in range(0,interfaces_count):
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no interface'}
            return {'status': False, 'error': unpackingerror}

        ## The interface should point to a valid class
        interface_index = int.from_bytes(checkbytes, byteorder='big')
        if not interface_index in class_table:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid interface in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

    ## fields_count
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no fields_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    fields_count = int.from_bytes(checkbytes, byteorder='big')

    ## read the fields, section 4.5
    for i in range(0,fields_count):
        ## access flags
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for access_flags'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## field name index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for name index'}
            return {'status': False, 'error': unpackingerror}
        field_name_index = int.from_bytes(checkbytes, byteorder='big')

        ## field_name_index has to be a valid entry in the constant pool
        if not field_name_index in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid name_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## field descriptor index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for name index'}
            return {'status': False, 'error': unpackingerror}
        field_descriptor_index = int.from_bytes(checkbytes, byteorder='big')

        ## field_descriptor_index has to be a valid entry in
        ## the constant pool
        if not field_descriptor_index in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid descriptor_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## finally the attributes count
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

    ## methods_count
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no methods_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2
    methods_count = int.from_bytes(checkbytes, byteorder='big')

    ## read the methods, section 4.6
    for i in range(0,methods_count):
        ## access flags
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no methods'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## name index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no methods'}
            return {'status': False, 'error': unpackingerror}

        method_name_index = int.from_bytes(checkbytes, byteorder='big')

        ## method_name_index has to be a valid entry in the constant pool
        if not method_name_index in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid name_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## descriptor index
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'no methods'}
            return {'status': False, 'error': unpackingerror}

        method_descriptor_index = int.from_bytes(checkbytes, byteorder='big')

        ## method_descriptor_index has to be a valid entry in the constant pool
        if not method_descriptor_index in constant_pool:
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

            ## attribute_name_index has to be a valid entry
            ## in the constant pool
            if not attribute_name_index in constant_pool:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not a valid name_index in constant pool'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

            ## length of the attribute
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

    ## attributes_count
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'no attributes_count'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    attributes_count = int.from_bytes(checkbytes, byteorder='big')

    ## read the attributes, section 4.7
    for i in range(0,attributes_count):
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough attributes'}
            return {'status': False, 'error': unpackingerror}

        attribute_name_index = int.from_bytes(checkbytes, byteorder='big')

        ## attribute_name_index has to be a valid entry in the constant pool
        if not attribute_name_index in constant_pool:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not a valid name_index in constant pool'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

        ## length of the attribute
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
        unpackedsize += attribute_info_length

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('java class')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
               'filesandlabels': unpackedfilesandlabels}

    ## else carve the file. The name of the class file can often
    ## be derived from the class data itself.
    if this_class_index in class_table:
        ## sometimes there is a full path inside the class file
        ## This can be found by first finding the right class
        ## in the constant pool and then using this index to
        ## find the corresponding name in the constant pool.
        if  class_table[this_class_index] in constant_pool:
            classname = os.path.basename(constant_pool[class_table[this_class_index]])
            ## sometimes the name ends in .class, but sometimes
            ## it doesn't, so add it.
            if not classname.endswith('.class'):
                classname += '.class'
        else:
            ## name could not be found in the constant pool
            ## so just give it a name
            classname = "unpacked.class"
    else:
        ## It is anonymous, so just give it a name
        classname = "unpacked.class"

    outfilename = os.path.join(unpackdir, classname)
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['java class', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
           'filesandlabels': unpackedfilesandlabels}

## Android Dalvik
##
## https://source.android.com/devices/tech/dalvik/dex-format
##
## Internet archive link:
##
## http://web.archive.org/web/20180520110013/https://source.android.com/devices/tech/dalvik/dex-format
##
## (sections "File layout" and "Items and related structures")
def unpackDex(filename, offset, unpackdir, temporarydirectory, dryrun=False, verifychecksum=True):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}

    if filesize - offset < 70:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip over the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then the version. In the specification it is part of
    ## DEX_FILE_MAGIC, but check it separately here to filter
    ## any false positives.

    dexversions = [b'035\x00', b'037\x00', b'038\x00', b'039\x00']

    checkbytes = checkfile.read(4)
    if not checkbytes in dexversions:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong Dex version'}
        return {'status': False, 'error': unpackingerror}
    dexversion = checkbytes
    unpackedsize += 4

    ## first check if the file is little endian. The endianness
    ## bytes can be found at offset 40
    oldoffset = checkfile.tell()
    checkfile.seek(offset+40)
    checkbytes = checkfile.read(4)

    if int.from_bytes(checkbytes, byteorder='little') != 0x12345678:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'incorrect endianness bytes'}
        return {'status': False, 'error': unpackingerror}

    ## return to the old offset
    checkfile.seek(oldoffset)

    ## then the adler checksum
    checkbytes = checkfile.read(4)
    adlerchecksum = int.from_bytes(checkbytes, byteorder='little')

    ## then the signature
    signature = checkfile.read(20)

    ## then the file size
    checkbytes = checkfile.read(4)
    dexsize = int.from_bytes(checkbytes, byteorder='little')
    if offset + dexsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'declared size bigger than file'}
        return {'status': False, 'error': unpackingerror}

    ## header size
    checkbytes = checkfile.read(4)
    headersize = int.from_bytes(checkbytes, byteorder='little')
    if headersize != 0x70:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong header size'}
        return {'status': False, 'error': unpackingerror}

    ## skip the endianness bit
    checkfile.seek(4, os.SEEK_CUR)

    ## link size
    checkbytes = checkfile.read(4)
    linksize = int.from_bytes(checkbytes, byteorder='little')

    ## link offset
    checkbytes = checkfile.read(4)
    linkoffset = int.from_bytes(checkbytes, byteorder='little')

    if linkoffset != 0:
        if offset + linkoffset + linksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'link section outside of file'}
            return {'status': False, 'error': unpackingerror}

    ## map item offset, "must be non-zero"
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

    ## string ids size
    checkbytes = checkfile.read(4)
    stringidssize = int.from_bytes(checkbytes, byteorder='little')

    ## string ids offset
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
        ## "0 if string_ids_size == 0"
        if stringidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'strings section/strings size mismatch'}
            return {'status': False, 'error': unpackingerror}

    ## type_ids_size, "at most 65535"
    checkbytes = checkfile.read(4)
    typeidssize = int.from_bytes(checkbytes, byteorder='little')
    if typeidssize > 65535:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'too many type identifiers'}
        return {'status': False, 'error': unpackingerror}

    ## type ids offset
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
        ## "0 if type_ids_size == 0"
        if typeidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'type section/type size mismatch'}
            return {'status': False, 'error': unpackingerror}

    ## proto ids size, "at most 65535"
    checkbytes = checkfile.read(4)
    protoidssize = int.from_bytes(checkbytes, byteorder='little')
    if protoidssize > 65535:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'too many type identifiers'}
        return {'status': False, 'error': unpackingerror}

    ## proto ids offset
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
        ## "0 if proto_ids_size == 0"
        if protoidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype section/prototype size mismatch'}
            return {'status': False, 'error': unpackingerror}

    ## fields ids size
    checkbytes = checkfile.read(4)
    fieldsidssize = int.from_bytes(checkbytes, byteorder='little')

    ## fields ids offset
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
        ## "0 if field_ids_size == 0"
        if fieldsidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'fields section/fields size mismatch'}
            return {'status': False, 'error': unpackingerror}

    ## method ids size
    checkbytes = checkfile.read(4)
    methodidssize = int.from_bytes(checkbytes, byteorder='little')

    ## method ids offset
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
        ## "0 if method_ids_size == 0"
        if methodidssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'methods section/methods size mismatch'}
            return {'status': False, 'error': unpackingerror}

    ## class definitions size
    checkbytes = checkfile.read(4)
    classdefssize = int.from_bytes(checkbytes, byteorder='little')

    ## class definitions offset
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
        ## "0 if class_defs_size == 0"
        if classdefssize != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'class definitions section/class definitions size mismatch'}
            return {'status': False, 'error': unpackingerror}

    ## data size, "Must be an even multiple of sizeof(uint)"
    checkbytes = checkfile.read(4)
    datasize = int.from_bytes(checkbytes, byteorder='little')
    if (datasize//4)%2 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'incorrect data size'}
        return {'status': False, 'error': unpackingerror}

    ## data offset
    checkbytes = checkfile.read(4)
    dataoffset = int.from_bytes(checkbytes, byteorder='little')

    if offset + dataoffset + datasize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'data outside of file'}
        return {'status': False, 'error': unpackingerror}

    if verifychecksum:
        ## jump to byte 12 and read all data
        checkfile.seek(offset+12)

        ## store the Adler32 of the uncompressed data
        dexadler = zlib.adler32(b'')
        dexsha1 = hashlib.new('sha1')

        ## first read 20 bytes just relevant for the Adler32
        checkbytes = checkfile.read(20)
        dexadler = zlib.adler32(checkbytes, dexadler)

        ## read all data to check the Adler32 checksum and the SHA1 checksum
        readsize = 10000000
        while True:
            checkbytes = checkfile.read(readsize)
            if checkbytes == b'':
                break
            dexadler = zlib.adler32(checkbytes, dexadler)
            dexsha1.update(checkbytes)

        if dexadler != adlerchecksum:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong Adler32'}
            return {'status': False, 'error': unpackingerror}

        if dexsha1.digest() != signature:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'wrong SHA1'}
            return {'status': False, 'error': unpackingerror}

    ## There are two ways to access the data: the first is to use the
    ## so called "map list" (the easiest). The second is to walk all the
    ## items separately.
    ## In this implementation the map list is primarily used, with the
    ## other data used for additional sanity checks.

    ## jump to the offset of the string identifiers list
    checkfile.seek(offset + stringidsoffset)

    ## keep track of the string identifiers
    stringids = {}

    ## keep track of the type identifiers
    typeids = {}

    ## some regex for sanity checks
    reshorty = re.compile('(?:V|[ZBSCIJFDL])[ZBSCIJFDL]*$')

    ## read each string_id_item, which is an offset into the data section
    for i in range(0,stringidssize):
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

        ## store the old offset
        oldoffset = checkfile.tell()

        ## then jump to the new offset
        checkfile.seek(offset + string_data_offset)

        ## encountered. The first few bytes will be the size in
        ## ULEB128 encoding:
        ##
        ## https://en.wikipedia.org/wiki/LEB128
        stringiddata = b''
        while True:
            checkbytes = checkfile.read(1)
            if checkbytes == b'\x00':
                break
            stringiddata += checkbytes
        for s in enumerate(stringiddata):
            if s[1] & 0x80 == 0x80:
                continue

            ## The string data itself is in Modified UTF-8 encoding.
            ## https://en.wikipedia.org/wiki/UTF-8#Modified_UTF-8
            stringid = stringiddata[s[0]+1:].replace(b'\xc0\x80', b'\x00')

            ## several characters have been replaced as well (surrogate)
            ## TODO

            stringid = stringid.decode()
            stringids[i] = stringid
            break

        ## and return to the old offset
        checkfile.seek(oldoffset)

    ## jump to the offset of the string identifiers list
    checkfile.seek(offset + typeidsoffset)

    ## read each type_id_item. These have to be valid ids in the
    ## string identifier table
    for i in range(0,typeidssize):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for string identifier offset'}
            return {'status': False, 'error': unpackingerror}
        descriptor_idx = int.from_bytes(checkbytes, byteorder='little')

        if not descriptor_idx in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'type identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}
        typeids[i] = stringids[descriptor_idx]

    ## jump to the offset of the prototype identifiers list
    checkfile.seek(offset + protoidsoffset)

    ## read each proto_id_item
    for i in range(0,protoidssize):
        ## first an index into the string identifiers list
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for prototype identifier offset'}
            return {'status': False, 'error': unpackingerror}
        shorty_idx = int.from_bytes(checkbytes, byteorder='little')

        if not shorty_idx in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}

        ## the shorty index points to a string that must conform
        ## to ShortyDescription syntax (see specifications)
        if reshorty.match(stringids[shorty_idx]) == None:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid prototype identifier'}
            return {'status': False, 'error': unpackingerror}

        ## then the return type index, which has to be a valid
        ## index into the type ids list
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for prototype return identifier offset'}
            return {'status': False, 'error': unpackingerror}
        return_type_idx = int.from_bytes(checkbytes, byteorder='little')

        if not return_type_idx in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'prototype return type not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        ## finally the parameters offset. This can either by 0 or
        ## a valid offset into the data section.
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

    ## jump to the offset of the field identifiers list
    checkfile.seek(offset + fieldsidsoffset)

    ## read each field_id_item
    for i in range(0,fieldsidssize):
        ## first an index into the string identifiers list
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        class_idx = int.from_bytes(checkbytes, byteorder='little')

        if not class_idx in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        ## "must be a class type"
        if not typeids[class_idx].startswith('L'):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier does not point to a class'}
            return {'status': False, 'error': unpackingerror}

        ## type_idx
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        type_idx = int.from_bytes(checkbytes, byteorder='little')

        if not type_idx in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        ## name_idx
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        name_idx = int.from_bytes(checkbytes, byteorder='little')

        if not name_idx in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}

    ## jump to the offset of the method identifiers list
    checkfile.seek(offset + methodidsoffset)

    ## read each method_id_item
    for i in range(0,methodidssize):
        ## first an index into the string identifiers list
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        class_idx = int.from_bytes(checkbytes, byteorder='little')

        if not class_idx in typeids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'method identifier not in type identifier list'}
            return {'status': False, 'error': unpackingerror}

        ## "must be a class type or array type"
        if not (typeids[class_idx].startswith('L') or typeids[class_idx].startswith('[')):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'method identifier does not point to a class'}
            return {'status': False, 'error': unpackingerror}

        ## proto_idx
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        proto_idx = int.from_bytes(checkbytes, byteorder='little')

        ## TODO: has to be a valid entry into the prototype list

        ## name_idx
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for type identifier offset'}
            return {'status': False, 'error': unpackingerror}
        name_idx = int.from_bytes(checkbytes, byteorder='little')

        if not name_idx in stringids:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'field identifier not in string identifier list'}
            return {'status': False, 'error': unpackingerror}

    ## Done with most of the sanity checks, so now use
    ## the map item instead, as it is more convenient.

    ## there is just a limited set of valid map item types
    validmapitems = set([0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
                         0x0006, 0x0007, 0x0008, 0x1000, 0x1001, 0x1002,
                         0x1003, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
                         0x2005, 0x2006])

    ## map offset "should be to an offset in the data section"
    if mapoffset < dataoffset:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'map item not in data section'}
        return {'status': False, 'error': unpackingerror}

    ## jump to the offset of the map item
    checkfile.seek(offset + mapoffset)

    ## store the types to offsets, plus the amount of map type items
    maptypetooffsets = {}

    seenmaptypes = set()

    ## parse map_list
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
        if not maptype in validmapitems:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid map type'}
            return {'status': False, 'error': unpackingerror}

        ## map types can appear at most once
        if maptype in seenmaptypes:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'duplicate map type'}
            return {'status': False, 'error': unpackingerror}
        seenmaptypes.add(maptype)

        ## unused
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
        ## else carve the file
        outfilename = os.path.join(unpackdir, "classes.dex")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfilename, ['dex', 'android', 'unpacked']))

    checkfile.close()
    return {'status': True, 'length': unpackedsize, 'labels': labels,
           'filesandlabels': unpackedfilesandlabels}

## Android Dalvik, optimized
##
## https://android.googlesource.com/platform/dalvik.git/+/master/libdex/DexFile.h
##
## Internet archive link:
##
## http://web.archive.org/web/20180816094438/https://android.googlesource.com/platform/dalvik.git/+/master/libdex/DexFile.h
##
## (struct DexOptHeader and DexFile)
def unpackOdex(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}

    if filesize < 40:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    ## open the file and skip over the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then the version. So far only one has been released but
    ## it could be that more will be released, so make it extensible.
    odexversions = [b'036\x00']

    checkbytes = checkfile.read(4)
    if not checkbytes in odexversions:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong Odex version'}
        return {'status': False, 'error': unpackingerror}
    dexversion = checkbytes
    unpackedsize += 4

    ## file offset to Dex header
    checkbytes = checkfile.read(4)
    dexoffset = int.from_bytes(checkbytes, byteorder='little')

    ## dex length
    checkbytes = checkfile.read(4)
    dexlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + dexlength + dexoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Dex file outside of file'}
        return {'status': False, 'error': unpackingerror}

    maxunpack = dexoffset + dexlength

    ## dependency table offset
    checkbytes = checkfile.read(4)
    depsoffset = int.from_bytes(checkbytes, byteorder='little')

    ## dependency table length
    checkbytes = checkfile.read(4)
    depslength = int.from_bytes(checkbytes, byteorder='little')
    if offset + depslength + depsoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Dependency table outside of file'}
        return {'status': False, 'error': unpackingerror}

    maxunpack = max(maxunpack, depsoffset + depslength)

    ## optimized table offset
    checkbytes = checkfile.read(4)
    optoffset = int.from_bytes(checkbytes, byteorder='little')

    ## optimized table length
    checkbytes = checkfile.read(4)
    optlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + optlength + optoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Optimized table outside of file'}
        return {'status': False, 'error': unpackingerror}

    maxunpack = max(maxunpack, optoffset + optlength)

    ## skip the flags
    checkfile.seek(4, os.SEEK_CUR)

    ## Adler32 checksum
    checkbytes = checkfile.read(4)
    adlerchecksum = int.from_bytes(checkbytes, byteorder='little')

    ## store the Adler32 of the uncompressed data
    dexadler = zlib.adler32(b'')

    ## first the deps
    checkfile.seek(offset+depsoffset)
    checkbytes = checkfile.read(depslength)
    dexadler = zlib.adler32(checkbytes, dexadler)

    ## then the optimized table
    checkfile.seek(offset+optoffset)
    checkbytes = checkfile.read(optlength)
    dexadler = zlib.adler32(checkbytes, dexadler)

    if dexadler != adlerchecksum:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong Adler32'}
        return {'status': False, 'error': unpackingerror}

    ## now check to see if it is a valid Dex. This is extremely
    ## unlikely at this point.
    dryrun = True
    verifychecksum = False
    dexres = unpackDex(filename, dexoffset, unpackdir, temporarydirectory, dryrun, verifychecksum)
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

    ## else carve the file
    outfilename = os.path.join(unpackdir, "unpacked.odex")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((outfilename, ['dex', 'android', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
           'filesandlabels': unpackedfilesandlabels}

## snappy
##
## https://pypi.python.org/pypi/python-snappy
## https://github.com/google/snappy/blob/master/framing_format.txt
## Test files can be created with snzip: https://github.com/kubo/snzip
## This only unpacks snzip's "framing2" format
def unpackSnappy(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    checkfile = open(filename, 'rb')

    ## skip the stream identifier stream (section 4.1)
    checkfile.seek(offset+10)
    unpackedsize += 10

    ## in practice just a few chunks are used
    validchunktypes = [b'\x00', b'\x01', '\xfe']

    possibledata = False

    ## then process all the frames
    while True:
        ## first the stream identifier
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
            break
        if not checkbytes in validchunktypes:
            ## There is no explicit end of file identifier
            ## so for carving assume that the end of
            ## stream has been reached
            break
        unpackedsize += 1
        ## then the length of the chunk
        checkbytes = checkfile.read(3)
        if len(checkbytes) != 3:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for chunk length'}
            return {'status': False, 'error': unpackingerror}

        ## each chunk has a length. It could be that data has been
        ## appended and that it starts with a valid chunk type (false
        ## positive). In that case stop processing the file and exit
        ## in case no chunks were unpacked at all.
        chunklength = int.from_bytes(checkbytes, byteorder='little')
        if checkfile.tell() + chunklength > filesize:
            if not possibledata:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'chunk cannot be outside of file'}
                return {'status': False, 'error': unpackingerror}
            ## adjust the counter
            unpackedsize -= 1
            break
        possibledata = True
        unpackedsize += 3 + chunklength
        checkfile.seek(chunklength, os.SEEK_CUR)

    outfilename = os.path.join(unpackdir, "unpacked-from-snappy")
    outfile = open(outfilename, 'wb')

    ## start at the beginning of the frame
    checkfile.seek(offset)

    ## now carve the file (if necessary)
    if filesize == offset + unpackedsize:
        try:
            snappy.stream_decompress(checkfile, outfile)
        except:
            outfile.close()
            os.unlink(outfilename)
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid Snappy data'}
            return {'status': False, 'error': unpackingerror}
        if offset == 0 and unpackedsize == filesize:
            labels += ['snappy', 'compressed']
        outfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((outfilename, []))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
               'filesandlabels': unpackedfilesandlabels}
    else:
        tmpfilename = os.path.join(unpackdir, "unpacked-from-snappy.sn")
        tmpfile = open(tmpfilename, 'wb')
        os.sendfile(tmpfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        checkfile.close()
        tmpfile.close()

        ## reopen the temporary file as read only
        tmpfile = open(tmpfilename, 'rb')
        tmpfile.seek(0)

        try:
            snappy.stream_decompress(tmpfile, outfile)
        except Exception as e:
            outfile.close()
            tmpfile.close()
            os.unlink(outfilename)
            os.unlink(tmpfilename)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid Snappy data'}
            return {'status': False, 'error': unpackingerror}

        outfile.close()
        tmpfile.close()
        os.unlink(tmpfilename)

        unpackedfilesandlabels.append((outfilename, []))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
               'filesandlabels': unpackedfilesandlabels}

    outfile.close()
    os.unlink(outfilename)
    checkfile.close()

    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'invalid Snappy file'}
    return {'status': False, 'error': unpackingerror}

## The ELF format is documented in numerous places:
##
## https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
## http://refspecs.linuxfoundation.org/elf/elf.pdf
## https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-43405/index.html
## https://android.googlesource.com/platform/art/+/master/runtime/elf.h
def unpackELF(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## ELF header is 52 bytes
    if filesize - offset < 52:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4
    is64bit = False
    bigendian = False

    ## check if the file is 32 bit or 64 bit
    checkbytes = checkfile.read(1)
    elfclass = ord(checkbytes)
    if elfclass == 0 or elfclass > 2:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid ELF class'}
        return {'status': False, 'error': unpackingerror}
    if elfclass == 2:
        is64bit = True
    unpackedsize += 1

    if is64bit:
        ## 64 bit ELF header is 52 bytes
        if filesize - offset < 64:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'not enough data'}
            return {'status': False, 'error': unpackingerror}

    ## check endianness of the file
    checkbytes = checkfile.read(1)
    dataencoding = ord(checkbytes)
    if dataencoding == 0 or dataencoding > 2:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid ELF data encoding'}
        return {'status': False, 'error': unpackingerror}
    if dataencoding == 2:
        bigendian = True
    unpackedsize += 1

    ## version (in e_ident), has to be 1
    checkbytes = checkfile.read(1)
    elfversion = ord(checkbytes)
    if elfversion != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid ELF version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## OS ABI, not accurate, often set to 0
    checkbytes = checkfile.read(1)
    osabi = ord(checkbytes)
    unpackedsize += 1

    ## ABI version, not accurate, often set to 0
    checkbytes = checkfile.read(1)
    abiversion = ord(checkbytes)
    unpackedsize += 1

    ## padding bytes, skip
    checkfile.seek(7, os.SEEK_CUR)
    unpackedsize += 7

    ## ELF type
    checkbytes = checkfile.read(2)
    if bigendian:
        elftype = int.from_bytes(checkbytes, byteorder='big')
    else:
        elftype = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## ELF machine
    checkbytes = checkfile.read(2)
    if bigendian:
        elfmachine = int.from_bytes(checkbytes, byteorder='big')
    else:
        elfmachine = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## ELF version
    checkbytes = checkfile.read(4)
    if bigendian:
        elfversion = int.from_bytes(checkbytes, byteorder='big')
    else:
        elfversion = int.from_bytes(checkbytes, byteorder='little')
    if elfversion != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid ELF version'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    ## e entry_point
    if is64bit:
        checkbytes = checkfile.read(8)
    else:
        checkbytes = checkfile.read(4)
    if bigendian:
        entry_point = int.from_bytes(checkbytes, byteorder='big')
    else:
        entry_point = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4
    if is64bit:
        unpackedsize += 4

    ## program header offset
    if is64bit:
        checkbytes = checkfile.read(8)
    else:
        checkbytes = checkfile.read(4)
    if bigendian:
        phoff = int.from_bytes(checkbytes, byteorder='big')
    else:
        phoff = int.from_bytes(checkbytes, byteorder='little')
    if offset + phoff > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'program header outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4
    if is64bit:
        unpackedsize += 4

    ## section header offset
    if is64bit:
        checkbytes = checkfile.read(8)
    else:
        checkbytes = checkfile.read(4)
    if bigendian:
        shoff = int.from_bytes(checkbytes, byteorder='big')
    else:
        shoff = int.from_bytes(checkbytes, byteorder='little')
    if offset + shoff > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'section header outside of file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4
    if is64bit:
        unpackedsize += 4

    ## flags, don't process
    checkbytes = checkfile.read(4)
    if bigendian:
        elfflags = int.from_bytes(checkbytes, byteorder='big')
    else:
        elfflags = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## header size: 64 for 64 bit, 52 for 32 bit. There might be other
    ## sizes but these are by far the most common.
    checkbytes = checkfile.read(2)
    if bigendian:
        elfheadersize = int.from_bytes(checkbytes, byteorder='big')
    else:
        elfheadersize = int.from_bytes(checkbytes, byteorder='little')
    if (is64bit and elfheadersize != 64) or (not is64bit and elfheadersize != 52):
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'wrong ELF header size'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## program header table entry size
    checkbytes = checkfile.read(2)
    if bigendian:
        phentrysize = int.from_bytes(checkbytes, byteorder='big')
    else:
        phentrysize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## program header table entries
    checkbytes = checkfile.read(2)
    if bigendian:
        phnum = int.from_bytes(checkbytes, byteorder='big')
    else:
        phnum = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## section header table entry size
    checkbytes = checkfile.read(2)
    if bigendian:
        shentrysize = int.from_bytes(checkbytes, byteorder='big')
    else:
        shentrysize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## section header table entries
    checkbytes = checkfile.read(2)
    if bigendian:
        shnum = int.from_bytes(checkbytes, byteorder='big')
    else:
        shnum = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 2

    ## section header index for section names
    checkbytes = checkfile.read(2)
    if bigendian:
        shstrndx = int.from_bytes(checkbytes, byteorder='big')
    else:
        shstrndx = int.from_bytes(checkbytes, byteorder='little')
    if shstrndx > shnum:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid index for section header table entry'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    ## some sanity checks for size
    if offset + phoff + phentrysize * phnum > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'program headers outside of file'}
        return {'status': False, 'error': unpackingerror}

    if offset + shoff + shentrysize * shnum > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'program headers outside of file'}
        return {'status': False, 'error': unpackingerror}

    ## program header and section headers cannot overlap
    if phoff < shoff and phoff + phentrysize * phnum > shoff:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'program headers and section headers overlap'}
        return {'status': False, 'error': unpackingerror}

    if shoff < phoff and shoff + shentrysize * shnum > phoff:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'program headers and section headers overlap'}
        return {'status': False, 'error': unpackingerror}

    maxoffset = 0

    ## sanity check for each of the program headers
    checkfile.seek(offset + phoff)
    unpackedsize = phoff
    for i in range(0, phnum):
        ## read the program header entry
        checkbytes = checkfile.read(4)
        unpackedsize += 4

        ## p_flags (64 bit only)
        if is64bit:
            checkbytes = checkfile.read(4)
            unpackedsize += 4

        ## p_offset
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        if bigendian:
            p_offset = int.from_bytes(checkbytes, byteorder='big')
        else:
            p_offset = int.from_bytes(checkbytes, byteorder='little')
        ## sanity check
        if offset + p_offset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'program header outside file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

        ## virtual address, skip
        if is64bit:
            checkbytes = checkfile.read(8)
            unpackedsize += 8
        else:
            checkbytes = checkfile.read(4)
            unpackedsize += 4

        ## physical address, skip
        if is64bit:
            checkbytes = checkfile.read(8)
            unpackedsize += 8
        else:
            checkbytes = checkfile.read(4)
            unpackedsize += 4

        ## filesz
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        if bigendian:
            p_filesz = int.from_bytes(checkbytes, byteorder='big')
        else:
            p_filesz = int.from_bytes(checkbytes, byteorder='little')
        ## sanity check
        if offset + p_offset + p_filesz > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'program header outside file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

        maxoffset = max(maxoffset, p_offset + p_filesz)

        ## memory size, skip for now
        if is64bit:
            checkbytes = checkfile.read(8)
            unpackedsize += 8
        else:
            checkbytes = checkfile.read(4)
            unpackedsize += 4

        ## p_flags (32 bit only)
        if not is64bit:
            checkbytes = checkfile.read(4)
            unpackedsize += 4

        ## palign, skip for now
        if is64bit:
            checkbytes = checkfile.read(8)
            unpackedsize += 8
        else:
            checkbytes = checkfile.read(4)
            unpackedsize += 4

    sectionheaders = {}

    ## sanity check for each of the section headers
    checkfile.seek(offset + shoff)
    unpackedsize = shoff
    for i in range(0, shnum):
        sectionheaders[i] = {}

        ## sh_name, should be a valid index into SHT_STRTAB
        checkbytes = checkfile.read(4)
        if bigendian:
            sh_name = int.from_bytes(checkbytes, byteorder='big')
        else:
            sh_name = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        sectionheaders[i]['sh_name_offset'] = sh_name

        ## sh_type
        checkbytes = checkfile.read(4)
        if bigendian:
            sh_type = int.from_bytes(checkbytes, byteorder='big')
        else:
            sh_type = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        sectionheaders[i]['sh_type'] = sh_type

        ## sh_flags
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        if bigendian:
            sh_flags = int.from_bytes(checkbytes, byteorder='big')
        else:
            sh_flags = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

        ## sh_addr, skip
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

        ## sh_offset
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        if bigendian:
            sh_offset = int.from_bytes(checkbytes, byteorder='big')
        else:
            sh_offset = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

        sectionheaders[i]['sh_offset'] = sh_offset

        ## sh_size
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        if bigendian:
            sh_size = int.from_bytes(checkbytes, byteorder='big')
        else:
            sh_size = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

        sectionheaders[i]['sh_size'] = sh_size

        ## sanity checks, except if a section is marked as SHT_NOBITS
        ## http://web.archive.org/web/20141027140248/http://wiki.osdev.org:80/ELF_Tutorial#The_BSS_and_SHT_NOBITS
        if sh_type != 8:
            if offset + sh_offset + sh_size > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'section header outside file'}
                return {'status': False, 'error': unpackingerror}

            maxoffset = max(maxoffset, sh_offset + sh_size)

        ## sh_link, skip for now
        checkbytes = checkfile.read(4)
        unpackedsize += 4

        ## sh_info, skip for now
        checkbytes = checkfile.read(4)
        unpackedsize += 4

        ## sh_addralign, skip for now
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

        ## sh_entsize, skip for now
        if is64bit:
            checkbytes = checkfile.read(8)
        else:
            checkbytes = checkfile.read(4)
        unpackedsize += 4
        if is64bit:
            unpackedsize += 4

    maxoffset = max(maxoffset, unpackedsize)

    ## entire file is ELF
    if offset == 0 and maxoffset == filesize:
        checkfile.close()
        labels.append('elf')
        return {'status': True, 'length': maxoffset, 'labels': labels,
               'filesandlabels': unpackedfilesandlabels}

    ## TODO: carving

    checkfile.close()
    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'invalid ELF file'}
    return {'status': False, 'error': unpackingerror}

## An unpacker for the SWF format, able to carve/label zlib &
## LZMA compressed SWF files as well as uncompressed files.
## Uses the description of the SWF file format as described here:
##
## https://wwwimages2.adobe.com/content/dam/acom/en/devnet/pdf/swf-file-format-spec.pdf
##
## The format is described in chapter 2 and Appendix A.
def unpackSWF(filename, offset, unpackdir, temporarydirectory):
    filesize = filename.stat().st_size
    labels = []
    unpackedfilesandlabels = []
    unpackingerror = {}

    unpackedsize = 0

    ## First check if the file size is 8 bytes or more.
    ## If not, then it is not a valid SWF file
    if filesize - offset < 8:
        unpackingerror = {'offset': offset, 'reason': 'fewer than 8 bytes',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    ## Then open the file and read the first three bytes to see
    ## if they respond to any of these SWF types:
    ##
    ## * uncompressed
    ## * compressed with zlib
    ## * compressed with LZMA
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(3)
    if checkbytes == b'FWS':
        swftype = 'uncompressed'
    elif checkbytes == b'CWS':
        swftype = 'zlib'
    elif checkbytes == b'ZWS':
        swftype = 'lzma'
    else:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'no valid SWF header',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 3

    ## Then the version number
    ## As of August 2018 it is at 40:
    ## https://www.adobe.com/devnet/articles/flashplayer-air-feature-list.html
    swfversion = ord(checkfile.read(1))

    if swftype == 'zlib' and swfversion < 6:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'wrong SWF version number for zlib compression',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    if swftype == 'lzma' and swfversion < 13:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'wrong SWF version number for zlib compression',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    ## Then read four bytes and check the length (stored in
    ## little endian format).
    ## This length has different meanings depending on whether or not
    ## compression has been used.
    checkbytes = checkfile.read(4)
    storedfilelength = int.from_bytes(checkbytes, byteorder='little')
    if storedfilelength == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'invalid declared file length',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    ## first process uncompresed files
    if swftype == 'uncompressed':
        ## the stored file length is the length of the entire
        ## file, so it cannot be bigger than the size of the
        ## actual fle.
        if storedfilelength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'reason': 'wrong length',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

        ## read one byte to find how many bits are
        ## needed for RECT (SWF specification, chapter 1)
        ## highest bits are used for this
        checkbytes = checkfile.read(1)
        nbits = ord(checkbytes) >> 3

        ## go back one byte
        checkfile.seek(-1, os.SEEK_CUR)

        ## and read (5 + 4*nbits) bits, has to be byte aligned
        bitstoread = 5 + 4*nbits
        checkbytes = checkfile.read(math.ceil(bitstoread/8))

        ## now process all of the bits
        bitcounter = 5

        ## then the frame rate
        checkbytes = checkfile.read(2)
        framerate = int.from_bytes(checkbytes, byteorder='little')

        ## and the frame size
        checkbytes = checkfile.read(2)
        framesize = int.from_bytes(checkbytes, byteorder='little')

        ## then the tags
        endofswf = False
        while True:
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                 checkfile.close()
                 unpackingerror = {'offset': offset,
                                   'reason': 'not enough bytes for tag',
                                   'fatal': False}
                 return {'status': False, 'error': unpackingerror}
            tagcodeandlength = int.from_bytes(checkbytes, byteorder='little')
            tagtype = tagcodeandlength >> 6
            taglength = tagcodeandlength & 63
            if taglength == 0x3f:
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                     checkfile.close()
                     unpackingerror = {'offset': offset,
                                       'reason': 'not enough bytes for tag length',
                                       'fatal': False}
                     return {'status': False, 'error': unpackingerror}
                taglength = int.from_bytes(checkbytes, byteorder='little')
            if checkfile.tell() + taglength > filesize:
                 checkfile.close()
                 unpackingerror = {'offset': offset,
                                   'reason': 'not enough bytes for tag',
                                   'fatal': False}
                 return {'status': False, 'error': unpackingerror}

            ## a few sanity checks for known tags
            if tagtype == 1:
                ## a show frame tag has no body
                if taglength != 0:
                     checkfile.close()
                     unpackingerror = {'offset': offset,
                                       'reason': 'wrong length for ShowFrame tag',
                                       'fatal': False}
                     return {'status': False, 'error': unpackingerror}

            ## then skip tag length bytes
            checkfile.seek(taglength, os.SEEK_CUR)
            if tagtype == 0:
                ## end tag
                endofswf = True
                break
            if checkfile.tell() == filesize:
                break

        if not endofswf:
            checkfile.close()
            unpackingerror = {'offset': offset,
                              'reason': 'no end tag found',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

        unpackedsize = checkfile.tell() - offset
        if unpackedsize != storedfilelength:
            checkfile.close()
            unpackingerror = {'offset': offset,
                              'reason': 'stored file length does not match length of unpacked data',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

        if offset == 0 and unpackedsize == filesize:
            checkfile.close()
            labels += ['swf', 'video']
            return {'status': True, 'length': filesize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        ## Carve the file. It is anonymous, so just give it a name
        outfilename = os.path.join(unpackdir, "unpacked.swf")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        outlabels = ['swf', 'video', 'unpacked']
        unpackedfilesandlabels.append((outfilename, outlabels))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## the data is compressed, so keep reading the compressed data until it
    ## can no longer be uncompressed

    ## 8 bytes have already been read
    unpackedsize = 8

    ## read 1 MB chunks
    chunksize = 1024*1024

    if swftype == 'zlib':
        #payload = b''
        decompressor = zlib.decompressobj()
        checkbytes = bytearray(chunksize)
        decompressedlength = 0
        while True:
            checkfile.readinto(checkbytes)
            try:
                ## uncompress the data and count the length, but
                ## don't store the data.
                unpackeddata = decompressor.decompress(checkbytes)
                decompressedlength += len(unpackeddata)
                #payload += unpackeddata
                unpackedsize += len(checkbytes) - len(decompressor.unused_data)
                if len(decompressor.unused_data) != 0:
                    break
            except Exception as e:
                checkfile.close()
                unpackingerror = {'offset': offset,
                                  'reason': 'zlib decompression failure',
                                  'fatal': False}
                return {'status': False, 'error': unpackingerror}

        if not decompressedlength + 8 == storedfilelength:
            checkfile.close()
            unpackingerror = {'offset': offset,
                              'reason': 'length of decompressed data does not match declared length',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

        if offset == 0 and unpackedsize == filesize:
            checkfile.close()
            labels += ['swf', 'zlib compressed swf', 'video']
            return {'status': True, 'length': filesize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        ## Carve the file. It is anonymous, so just give it a name
        outfilename = os.path.join(unpackdir, "unpacked.swf")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        outlabels = ['swf', 'zlib compressed swf', 'video', 'unpacked']
        unpackedfilesandlabels.append((outfilename, outlabels))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## As standard LZMA decompression from Python does not
    ## like this format and neither does lzmacat, so some tricks are needed
    ## to be able to decompress this data.
    ##
    ## Also see:
    ##
    ## * https://bugzilla.mozilla.org/show_bug.cgi?format=default&id=754932
    ## * http://dev.offerhq.co/ui/assets/js/plupload/src/moxie/build/swf2lzma/swf2lzma.py

    checkbytes = checkfile.read(4)
    compressedlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + 12 + compressedlength + 5 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'reason': 'wrong length',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize = 12
    checkfile.seek(offset+12)

    ## now read 1 byte for the LZMA properties
    checkbytes = checkfile.read(1)
    unpackedsize += 1

    ## compute the LZMA properties, according to
    ## http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
    ## section 1.1
    props = ord(checkbytes)
    lzma_pb = props // (9 * 5)
    props -= lzma_pb * 9 * 5
    lzma_lp = props // 9
    lzma_lc = props - lzma_lp * 9

    ## and 4 for the dictionary size
    checkbytes = checkfile.read(4)
    dictionarysize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## Create a LZMA decompressor with custom filter, as the data
    ## is stored without LZMA headers.
    swf_filters = [
         {'id': lzma.FILTER_LZMA1,
          'dict_size': dictionarysize,
          'lc': lzma_lc,
          'lp': lzma_lp,
          'pb': lzma_pb},
    ]

    try:
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=swf_filters)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset,
                          'reason': 'unsupported LZMA properties',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    ## read 1 MB chunks
    #payload = b''
    checkbytes = bytearray(chunksize)
    decompressedlength = 0
    while True:
        checkfile.readinto(checkbytes)
        try:
            ## uncompress the data and count the length, but
            ## don't store the data.
            unpackeddata = decompressor.decompress(checkbytes)
            decompressedlength += len(unpackeddata)
            #payload += unpackeddata
            unpackedsize += len(checkbytes) - len(decompressor.unused_data)
            if len(decompressor.unused_data) != 0:
                break
        except Exception as e:
            checkfile.close()
            unpackingerror = {'offset': offset,
                              'reason': 'LZMA decompression failure',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

    if not decompressedlength + 8 == storedfilelength:
        checkfile.close()
        unpackingerror = {'offset': offset,
                          'reason': 'length of decompressed data does not match declared length',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels += ['swf', 'lzma compressed swf', 'video']
        return {'status': True, 'length': filesize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    ## Carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked.swf")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    outlabels = ['swf', 'lzma compressed swf', 'video', 'unpacked']
    unpackedfilesandlabels.append((outfilename, outlabels))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}
