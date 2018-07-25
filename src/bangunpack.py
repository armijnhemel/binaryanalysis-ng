#!/usr/bin/python3

## Built in carvers/verifiers/unpackers for various formats.
##
## Copyright 2018 - Armijn Hemel
## Licensed under the terms of the GNU Affero General Public License version 3
## SPDX-License-Identifier: AGPL-3.0-only
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
## 25. SGI image files
## 26. AIFF/AIFF-C
## 27. terminfo (little endian, including ncurses extension, does not
##     recognize some wide character versions)
## 28. AU (Sun/NeXT audio)
## 29. JFFS2 (uncompressed, zlib, LZMA from OpenWrt)
## 30. CPIO (various flavours, little endian)
## 31. Sun Raster files (standard type only)
## 32. Intel Hex (text files only)
## 33. Motorola SREC (text files only)
## 34. RPM (missing: delta RPM)
## 35. Apple Icon Image
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
## 10. Windows Compiled HTML Help (requires external tools, version 3 only)
## 11. Windows Imaging file format (requires external tools, single image only)
## 12. ext2/3/4 (missing: symbolic link support)
## 13. zstd (needs zstd package)
##
## For these unpackers it has been attempted to reduce disk I/O as much as possible
## using the os.sendfile() method, as well as techniques described in this blog
## post:
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

## some external packages that are needed
import PIL.Image

encodingstotranslate = [ 'utf-8','ascii','latin-1','euc_jp', 'euc_jis_2004'
                       , 'jisx0213', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2'
                       , 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext'
                       , 'iso2022_kr','shift_jis','shift_jis_2004'
                       , 'shift_jisx0213']

## Each unpacker has a specific interface:
##
## def unpacker(filename, offset, unpackdir)
##
## * filename: full file name
## * offset: offset inside the file where the file system, compressed file
##   media file possibly starts
## * unpackdir: the target directory where data should be written to
##
## The unpackers are supposed to return the following data (in this order):
##
## * unpack status (boolean) to indicate whether or not any data was unpacked
## * unpack size to indicate what part of the data was unpacked
## * a list of tuples (file, labels) that were unpacked from the file. The labels
##   could be used to indicate that a file has a certain status and that it should
##   not be unpacked as it is already known what the file is (example: PNG)
## * a list of labels for the file
## * a dict with a possible error. This is ignored if unpacking was successful.
##
## The error dict has the following items:
##
## * fatal: boolean to indicate whether or not the error is a fatal
##   error (such as disk full, etc.) so BANG should be stopped. Non-fatal
##   errors are format violations (files, etc.)
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
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []

    ## a list of valid WebP chunk FourCC
    ## also contains the deprecated FRGM
    validchunkfourcc = set([b'ALPH', b'ANIM', b'ANMF', b'EXIF', b'FRGM', b'ICCP', b'VP8 ', b'VP8L', b'VP8X', b'XMP '])
    (unpackstatus, unpackedsize, unpackedfiles, labels, error) = unpackRIFF(filename, offset, unpackdir, validchunkfourcc, 'WebP', b'WEBP', filesize)
    if unpackstatus:
        if offset == 0 and unpackedsize == filesize:
            labels += ['webp', 'graphics']
        for u in unpackedfiles:
            unpackedfilesandlabels.append((u, ['webp', 'graphics', 'unpacked']))
    return (unpackstatus, unpackedsize, unpackedfilesandlabels, labels, error)

## A verifier for the WAV file format.
## Uses the description of the WAV file format as described here:
##
## https://sites.google.com/site/musicgapi/technical-documents/wav-file-format
## http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
def unpackWAV(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []

    ## a list of valid WAV chunk FourCC
    validchunkfourcc = set([b'LGWV', b'bext', b'cue ', b'data', b'fact', b'fmt ', b'inst', b'labl', b'list', b'ltxt', b'note', b'plst', b'smpl'])
    (unpackstatus, unpackedsize, unpackedfiles, labels, error) = unpackRIFF(filename, offset, unpackdir, validchunkfourcc, 'WAV', b'WAVE', filesize)
    if unpackstatus:
        if offset == 0 and unpackedsize == filesize:
            labels += ['wav', 'audio']
        for u in unpackedfiles:
            unpackedfilesandlabels.append((u, ['wav', 'audio', 'unpacked']))
    return (unpackstatus, unpackedsize, unpackedfilesandlabels, labels, error)

## An unpacker for RIFF. This is a helper method used by unpackers for:
## * WebP
## * WAV
## * ANI
## https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
def unpackRIFF(filename, offset, unpackdir, validchunkfourcc, applicationname, applicationheader, filesize):
    labels = []
    ## First check if the file size is 12 bytes or more. If not, then it is not a valid RIFF file
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'reason': 'less than 12 bytes', 'fatal': False}
        return (False, 0, [], labels, unpackingerror)

    unpackedsize = 0

    ## Then open the file and read the first four bytes to see if they are "RIFF"
    checkfile = open(filename, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(4)
    if checkbytes != b'RIFF':
        checkfile.close()
        unpackingerror = {'offset': offset, 'reason': 'no valid RIFF header', 'fatal': False}
        return (False, 0, [], labels, unpackingerror)
    unpackedsize += 4

    ## Then read four bytes and check the length (stored in little endian format)
    checkbytes = checkfile.read(4)
    rifflength = int.from_bytes(checkbytes, byteorder='little')
    ## the data cannot go outside of the file
    if rifflength + 8 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'reason': 'wrong length', 'fatal': False}
        return (False, 0, [], labels, unpackingerror)
    unpackedsize += 4

    ## Then read four bytes and check if they match the supplied header
    checkbytes = checkfile.read(4)
    if checkbytes != applicationheader:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'reason': 'no valid %s header' % applicationname, 'fatal': False}
        return (False, 0, [], labels, unpackingerror)
    unpackedsize += 4

    ## then read chunks
    while checkfile.tell() != offset + rifflength + 8:
        haspadding = False
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset + unpackedsize, 'reason': 'no valid chunk header', 'fatal': False}
            return (False, 0, [], labels, unpackingerror)
        if not checkbytes in validchunkfourcc:
            checkfile.close()
            unpackingerror = {'offset': offset + unpackedsize, 'reason': 'no valid chunk FourCC %s' % checkbytes, 'fatal': False}
            return (False, 0, [], labels, unpackingerror)
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
            unpackingerror = {'offset': offset + unpackedsize, 'reason': 'wrong chunk length', 'fatal': False}
            return (False, 0, [], labels, unpackingerror)
        unpackedsize += 4

        ## finally skip over the bytes in the file
        if haspadding:
            checkfile.seek(curpos + chunklength-1)
            paddingbyte = checkfile.read(1)
            if not paddingbyte == b'\x00':
                checkfile.close()
                unpackingerror = {'offset': offset + unpackedsize, 'reason': 'wrong value for padding byte length', 'fatal': False}
                return (False, 0, [], labels, unpackingerror)
        else:
            checkfile.seek(curpos + chunklength)
        unpackedsize += chunklength

    ## extra sanity check to see if the size of the unpacked data
    ## matches the declared size from the header.
    if unpackedsize != rifflength + 8:
        checkfile.close()
        unpackingerror = {'offset': offset, 'reason': 'unpacked size does not match declared size', 'fatal': False}
        return (False, 0, [], labels, unpackingerror)

    ## if the entire file is the RIFF file, then label it as such
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('riff')
        return (True, unpackedsize, [], labels, {})

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked-%s" % applicationname.lower())
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    return(True, unpackedsize, [outfilename], labels, {})

## test files for ANI: http://www.anicursor.com/diercur.html
## http://fileformats.archiveteam.org/wiki/Windows_Animated_Cursor#Sample_files
def unpackANI(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []

    ## a list of valid ANI chunk FourCC
    validchunkfourcc = set([b'IART', b'ICON', b'INAM', b'LIST', b'anih', b'rate', b'seq '])
    (unpackstatus, unpackedsize, unpackedfiles, labels, error) = unpackRIFF(filename, offset, unpackdir, validchunkfourcc, 'ANI', b'ACON', filesize)
    if unpackstatus:
        if offset == 0 and unpackedsize == filesize:
            labels += ['ani', 'graphics']
        for u in unpackedfiles:
            unpackedfilesandlabels.append((u, ['ani', 'graphics', 'unpacked']))
    return (unpackstatus, unpackedsize, unpackedfilesandlabels, labels, error)

## PNG specifications can be found at:
##
## https://www.w3.org/TR/PNG/
##
## Section 5 describes the structure of a PNG file
def unpackPNG(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackedsize = 0
    unpackingerror = {}
    if filesize - offset < 57:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'File too small (less than 57 bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## open the file skip over the magic header bytes (section 5.2)
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+8)
    unpackedsize = 8

    ## Then process the PNG data. All data is in network byte order (section 7)
    ## First read the size of the first chunk, which is always 25 bytes (section 11.2.2)
    checkbytes = checkfile.read(25)
    if checkbytes[0:4] != b'\x00\x00\x00\x0d':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False, 'reason': 'no valid chunk length'}
        checkfile.close()
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## The first chunk *has* to be IHDR
    if checkbytes[4:8] != b'IHDR':
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False, 'reason': 'no IHDR header'}
        checkfile.close()
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## then compute the CRC32 of bytes 4 - 21 (header + data)
    ## and compare it to the CRC in the PNG file
    crccomputed = binascii.crc32(checkbytes[4:21])
    crcstored = int.from_bytes(checkbytes[21:25], byteorder='big')
    if crccomputed != crcstored:
        unpackingerror = {'offset': offset + unpackedsize, 'fatal': False, 'reason': 'Wrong CRC'}
        checkfile.close()
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 25

    ## Then move on to the next chunks in similar fashion (section 5.3)
    endoffilereached = False
    idatseen = False
    chunknames = set()
    while True:
        ## read the chunk size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False, 'reason': 'Could not read chunk size'}
            checkfile.close()
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        chunksize = int.from_bytes(checkbytes, byteorder='big')
        if offset + chunksize > filesize:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False, 'reason': 'PNG data bigger than file'}
            checkfile.close()
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## read the chunk type, plus the chunk data
        checkbytes = checkfile.read(4+chunksize)
        chunktype = checkbytes[0:4]
        if len(checkbytes) != 4+chunksize:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False, 'reason': 'Could not read chunk type'}
            checkfile.close()
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize += 4+chunksize

        ## compute the CRC
        crccomputed = binascii.crc32(checkbytes)
        checkbytes = checkfile.read(4)
        crcstored = int.from_bytes(checkbytes, byteorder='big')
        if crccomputed != crcstored:
            unpackingerror = {'offset': offset + unpackedsize, 'fatal': False, 'reason': 'Wrong CRC'}
            checkfile.close()
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'No IDAT found'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid PNG data according to PIL'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
            checkfile.close()
            labels += ['png', 'graphics']
            if animated:
                labels.append('animated')
                labels.append('apng')
            return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid PNG data according to PIL'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        if animated:
            unpackedfilesandlabels.append((outfilename, ['png', 'graphics', 'animated', 'apng', 'unpacked']))
        else:
            unpackedfilesandlabels.append((outfilename, ['png', 'graphics', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## There is no end of file, so it is not a valid PNG.
    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'No IEND found'}
    return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        checkfile = open(filename, 'rb')
        checkfile.seek(offset+3)
        unpackedsize += 3
        ## RFC 1952 http://www.zlib.org/rfc-gzip.html describes the flags, but omits the "encrytion" flag (bit 5)
        ##
        ## Python 3's zlib module does not support:
        ## * continuation of multi-part gzip (bit 2)
        ## * encrypt (bit 5)
        ##
        ## RFC 1952 says that bit 6 and 7 should not be set
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if (checkbytes[0] >> 2 & 1) == 1:
                ## continuation of multi-part gzip
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsupported multi-part gzip'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if (checkbytes[0] >> 5 & 1) == 1:
                ## encrypted
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsupported encrypted'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if (checkbytes[0] >> 6 & 1) == 1 or (checkbytes[0] >> 7 & 1) == 1:
                ## reserved
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not a valid gzip file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                xlen = int.from_bytes(checkbytes, byteorder='little')
                if checkfile.tell() + xlen > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extra data outside of file'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'file name data outside of file'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'comment data outside of file'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if (checkbytes[0] >> 1 & 1) == 1 and (checkbytes[0] >> 2 & 1) == 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong DEFLATE header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## go back one byte
        checkfile.seek(-1,os.SEEK_CUR)

        ## what follows next is raw deflate blocks. To unpack raw deflate data the windowBits have to be
        ## set to negative values: http://www.zlib.net/manual.html#Advanced
        ## First create a zlib decompressor that can decompress raw deflate
        ## https://docs.python.org/3/library/zlib.html#zlib.compressobj
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

        ## now start decompressing the data
        ## set the name of the file in case it is "anonymous data"
        ## otherwise just imitate whatever gunzip does. If the file has a
        ## name recorded in the file it will be renamed later.
        if filename.endswith('.gz'):
                outfilename = os.path.join(unpackdir, os.path.basename(filename)[:-3])
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
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'File not a valid gzip file'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                unpackedsize += len(checkbytes) - len(decompressor.unused_data)
                if decompressor.unused_data != b'':
                        break
        outfile.close()

        ## A valid gzip file has CRC32 and ISIZE at the end, so there should always be
        ## at least 8 bytes left for a valid file.
        if filesize - unpackedsize + offset < 8:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no CRC and ISIZE'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## first reset the file pointer until the end of the unpacked zlib data
        checkfile.seek(offset + unpackedsize)

        ## now compute the gzip CRC of the unocmpressed data and compare to
        ## the CRC stored in the file (RFC 1952, section 2.3.1)
        checkbytes = checkfile.read(4)
        unpackedsize += 4

        ## compute the ISIZE (RFC 1952, section 2.3.1)
        checkbytes = checkfile.read(4)
        checkfile.close()

        unpackedsize += 4

        ## this check is modulo 2^32
        isize = os.stat(outfilename).st_size % pow(2,32)
        if int.from_bytes(checkbytes, byteorder='little') != isize:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for ISIZE'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://en.wikipedia.org/wiki/BMP_file_format
def unpackBMP(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    ## first check if the data is large enough
    ## BMP header is 14 bytes, smallest DIB header is 12 bytes
    ## https://en.wikipedia.org/wiki/BMP_file_format#Bitmap_file_header
    if filesize - offset < 26:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'File too small (less than 26 bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for BMP file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## skip over 4 bytes of reserved data and read the offset of the BMP data
    checkfile.seek(4,os.SEEK_CUR)
    unpackedsize += 4
    checkbytes = checkfile.read(4)
    bmpoffset = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4
    ## the BMP cannot be outside the file
    if offset + bmpoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for BMP'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## read the first two bytes of the DIB header (DIB header size) as an extra sanity check.
    ## There are actually just a few supported values:
    ## https://en.wikipedia.org/wiki/BMP_file_format#DIB_header_(bitmap_information_header)
    checkbytes = checkfile.read(2)
    dibheadersize = int.from_bytes(checkbytes, byteorder='little')
    if not dibheadersize in set([12, 64, 16, 40, 52, 56, 108, 124]):
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid DIB header'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## check if the header size is inside the file
    if offset + 14 + dibheadersize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for DIB header'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## the BMP data offset is from the start of the BMP file. It cannot be inside
    ## the BMP header (14 bytes) or the DIB header (variable).
    if bmpoffset < dibheadersize + 14:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid BMP data offset'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 2

    if offset == 0 and bmpsize == filesize:
        ## now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid BMP according to PIL'}
            return (False, bmpsize, unpackedfilesandlabels, labels, unpackingerror)
        checkfile.close()

        labels.append('bmp')
        labels.append('graphics')
        return (True, bmpsize, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid JPEG data according to PIL'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    unpackedfilesandlabels.append((outfilename, ['bmp', 'graphics', 'unpacked']))
    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## wrapper for LZMA, with a few extra sanity checks based on LZMA format specifications.
def unpackLZMA(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    if filesize - offset < 13:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## There are many false positives for LZMA.
    ## The file lzma-file-format.txt in XZ file distributions describe the
    ## LZMA format. The first 13 bytes describe the header. The last
    ## 8 bytes of the header describe the file size.
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+5)
    checkbytes = checkfile.read(8)
    checkfile.close()

    ## first check if an actual length of the *uncompressed* data is stored, or
    ## if it is possibly stored as a stream. LZMA streams have 0xffffffff stored
    ## in the length field.
    ## http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
    if checkbytes != b'\xff\xff\xff\xff\xff\xff\xff\xff':
        lzmaunpackedsize = int.from_bytes(checkbytes, byteorder='little')
        if lzmaunpackedsize == 0:
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'declared size 0'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## XZ Utils cannot unpack or create files with size of 256 GiB or more
        if lzmaunpackedsize > 274877906944:
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'declared size too big'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    else:
        lzmaunpackedsize = -1

    return unpackLZMAWrapper(filename, offset, unpackdir, '.lzma', 'lzma', 'LZMA', lzmaunpackedsize)

## wrapper for both LZMA and XZ
## Uses standard Python code.
def unpackLZMAWrapper(filename, offset, unpackdir, extension, filetype, ppfiletype, lzmaunpackedsize):
    filesize = os.stat(filename).st_size
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
        ## no data could be successfully unpacked, so close the file and exit.
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not valid %s data' % ppfiletype}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## set the name of the file in case it is "anonymous data"
    ## otherwise just imitate whatever unxz and lzma do. If the file has a
    ## name recorded in the file it will be renamed later.
    if filetype == 'xz':
        if filename.endswith('.xz'):
                outfilename = os.path.join(unpackdir, os.path.basename(filename)[:-3])
        else:
                outfilename = os.path.join(unpackdir, "unpacked-from-%s" % filetype)
    elif filetype == 'lzma':
        if filename.endswith('.lzma'):
            outfilename = os.path.join(unpackdir, os.path.basename(filename)[:-5])
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
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'File not a valid %s file' % ppfiletype}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'File not a valid %s file' % ppfiletype}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## check if the length of the unpacked LZMA data is correct, but
    ## only if any unpacked length has been defined.
    if filetype == 'lzma' and lzmaunpackedsize != -1:
        if lzmaunpackedsize != os.stat(outfilename).st_size:
            os.unlink(outfilename)
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'length of unpacked %s data does not correspond with header' % ppfiletype}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    min_lzma = 256

    ## LZMA sometimes has bogus files filled with 0x00
    if os.stat(outfilename).st_size < min_lzma:
        pass

    if offset == 0 and unpackedsize == os.stat(filename).st_size:
        ## in case the file name ends in extension rename the file
        ## to mimic the behaviour of "unxz" and similar
        if filename.lower().endswith(extension):
            newoutfilename = os.path.join(unpackdir, os.path.basename(filename)[:-len(extension)])
            shutil.move(outfilename, newoutfilename)
            outfilename = newoutfilename
        labels += [filetype, 'compressed']
    unpackedfilesandlabels.append((outfilename, []))
    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## XZ unpacking works just like LZMA unpacking
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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        if filesize - offset < 44:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid version'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 1

        ## then 15 NUL bytes
        checkbytes = checkfile.read(15)
        if checkbytes != b'\x00' * 15:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'reserved bytes not 0'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'local of times set to not-permitted 0'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## the number of bytes of timezone abbreviation strings
        checkbytes = checkfile.read(4)
        tz_abbrevation_bytes = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        for i in range(0, transition_times):
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for transition time'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

        ## then a number of bytes, each serving as an index into
        ## the next field.
        for i in range(0, transition_times):
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for transition time'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1
                if ord(checkbytes) > local_times:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid index for transition time'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## now read a bunch of ttinfo entries
        for i in range(0, local_times):
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ttinfo GMT offsets'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## then the DST flag byte
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ttinfo DST info'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if not (ord(checkbytes) == 0 or ord(checkbytes) == 1):
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for ttinfo DST info'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

                ## then the abbreviation index, which points into the
                ## abbrevation strings, so cannot be larger than than tz_abbrevation_bytes
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ttinfo abbreviation index'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if ord(checkbytes) > tz_abbrevation_bytes:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for ttinfo abbreviation index'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

        ## then the abbrevation strings, as indicated by tz_abbrevation_bytes
        checkbytes = checkfile.read(tz_abbrevation_bytes)
        if len(checkbytes) != tz_abbrevation_bytes:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for abbreviation bytes'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += tz_abbrevation_bytes

        ## then 2 pairs of 4 bytes for each of the leap second entries
        for i in range(0, leap_cnt):
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for leap seconds'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for leap seconds'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

        ## then one byte for each of the standard/wall indicators
        for i in range(0, standard_indicators):
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for standard indicator'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

        ## then one byte for each of the UT/local indicators
        for i in range(0, ut_indicators):
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for UT indicator'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

        ## This is the end for version 0 timezone files
        if version == 0:
                if offset == 0 and unpackedsize == filesize:
                        checkfile.close()
                        labels.append('resource')
                        labels.append('timezone')
                        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                ## else carve the file
                outfilename = os.path.join(unpackdir, "unpacked-from-timezone")
                outfile = open(outfilename, 'wb')
                os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
                outfile.close()
                unpackedfilesandlabels.append((outfilename, ['timezone', 'resource', 'unpacked']))
                checkfile.close()
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## Then continue with version 2 data. The header is identical to the
        ## version 1 header.
        if offset + unpackedsize + 44 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for version 2 timezone header'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## first check the header
        checkbytes = checkfile.read(4)
        if checkbytes != b'TZif':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid magic for version 2 header'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## read the version
        checkbytes = checkfile.read(1)
        if checkbytes == b'\x32':
                newversion = 2
        elif checkbytes == b'\x33':
                newversion = 3
        else:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid version'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## The version has to be identical to the previously declard version
        if version != newversion:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'versions in headers don\'t match'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 1

        ## then 15 NUL bytes
        checkbytes = checkfile.read(15)
        if checkbytes != b'\x00' * 15:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'reserved bytes not 0'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'local of times set to not-permitted 0'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## the number of bytes of timezone abbreviation strings
        checkbytes = checkfile.read(4)
        tz_abbrevation_bytes = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        for i in range(0, transition_times):
                checkbytes = checkfile.read(8)
                if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for transition time'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 8

        ## then a number of bytes, each serving as an index into
        ## the next field.
        for i in range(0, transition_times):
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for transition time'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1
                if ord(checkbytes) > local_times:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid index for transition time'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## now read a bunch of ttinfo entries
        for i in range(0, local_times):
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ttinfo GMT offsets'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## then the DST flag byte
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ttinfo DST info'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if not (ord(checkbytes) == 0 or ord(checkbytes) == 1):
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for ttinfo DST info'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

                ## then the abbreviation index, which points into the
                ## abbrevation strings, so cannot be larger than tz_abbrevation_bytes
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ttinfo abbreviation index'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if ord(checkbytes) > tz_abbrevation_bytes:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for ttinfo abbreviation index'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

        ## then the abbrevation strings, as indicated by tz_abbrevation_bytes
        checkbytes = checkfile.read(tz_abbrevation_bytes)
        if len(checkbytes) != tz_abbrevation_bytes:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for abbreviation bytes'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += tz_abbrevation_bytes

        ## then 2 pairs of 4 bytes for each of the leap second entries
        for i in range(0, leap_cnt):
                checkbytes = checkfile.read(8)
                if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for leap seconds'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 8

                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for leap seconds'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

        ## then one byte for each of the standard/wall indicators
        for i in range(0, standard_indicators):
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for standard indicator'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

        ## then one byte for each of the UT/local indicators
        for i in range(0, ut_indicators):
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for UT indicator'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

        ## next comes a POSIX-TZ-environment-variable-style string (possibly empty)
        ## enclosed between newlines
        checkbytes = checkfile.read(1)
        if len(checkbytes) != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for POSIX TZ environment style string'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        if checkbytes != b'\n':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for POSIX TZ environment style string'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'enclosing newline for POSIX TZ environment style string not found'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1
                if checkbytes == b'\n':
                        break
                if not chr(ord(checkbytes)) in string.printable or chr(ord(checkbytes)) in string.whitespace:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid character in POSIX TZ environment style string'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels.append('resource')
                labels.append('timezone')
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file
        outfilename = os.path.join(unpackdir, "unpacked-from-timezone")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfilename, ['timezone', 'resource', 'unpacked']))
        checkfile.close()
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## unpacker for tar files. Uses the standard Python library.
## https://docs.python.org/3/library/tarfile.html
def unpackTar(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## tar is a concatenation of files. It could be that a tar file has been cut
    ## halfway but it might still be possible to extract some data.
    ## Use a file object so it is possible to start tar unpacking at arbitrary
    ## positions in the file.
    checkfile = open(filename, 'rb')

    ## seek to the offset where the tar is supposed to start. According to
    ## the documentation it should be opened at offset 0, but this works
    ## too.
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
                ## tar changes permissions after unpacking, so change them
                ## back to something a bit more sensible
                os.chmod(unpackedname, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
                if not os.path.isdir(unpackedname):
                    unpackedfilesandlabels.append((os.path.join(unpackdir, unpacktarinfo.name), []))
                elif unpacktarinfo.issym():
                    unpackedfilesandlabels.append((os.path.join(unpackdir, unpacktarinfo.name), ['symbolic link']))
                tounpack = ''
        except Exception as e:
            unpackedsize = oldunpackedsize
            tarerror = True
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': str(e)}
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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'Not a valid tar file'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)

    ## tar has finished, meaning it should also have read the termination
    ## blocks for the tar file, so set the unpacked size to just after where
    ## the tar module finished.
    unpackedsize = checkfile.tell() - offset

    ## Data was unpacked from the file, so the data up until now is
    ## definitely a tar, but is the rest of the file also part of the tar
    ## or of something else?
    ##
    ## Example: GNU tar tends to pad files with up to 20 blocks (512
    ## bytes each) filled with 0x00 although this heavily depends on
    ## the command line settings.
    ##
    ## This can be checked with GNU tar by inspecting the file with the options
    ## "itvRf" to the tar command:
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

    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Unix portable archiver
## https://en.wikipedia.org/wiki/Ar_%28Unix%29
## https://sourceware.org/binutils/docs/binutils/ar.html
def unpackAr(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    unpackedsize = 0

    if offset != 0:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Currently only works on whole files'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    if shutil.which('ar') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'ar program not found'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## first test the file to see if it is a valid file
    p = subprocess.Popen(['ar', 't', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (standard_out, standard_error) = p.communicate()
    if p.returncode != 0:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Not a valid ar file'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## then extract the file
    p = subprocess.Popen(['ar', 'x', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=unpackdir)
    (outputmsg, errormsg) = p.communicate()
    if p.returncode != 0:
        foundfiles = os.listdir(unpackdir)
        ## try to remove any files that were left behind
        for f in foundfiles:
            if os.path.isdir(os.path.join(unpackdir, f)):
                shutil.rmtree(os.path.join(unpackdir, f))
            else:
                os.unlink(os.path.join(unpackdir, f))

        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Not a valid ar file'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    foundfiles = os.listdir(unpackdir)
    labels += ['archive', 'ar']

    foundfiles = os.listdir(unpackdir)
    for f in foundfiles:
       outputfilename = os.path.join(unpackdir, f)
       unpackedfilesandlabels.append((outputfilename, []))
       if f == 'debian-binary':
           if filename.lower().endswith('.deb') or filename.lower().endswith('.udeb'):
               labels.append('debian')
               labels.append('deb')

    return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

## Unpacking for squashfs
## There are many different flavours of squashfs and configurations
## differ per Linux distribution.
## This is for the "vanilla" squashfs
def unpackSquashfs(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}

        unpackedsize = 0

        if shutil.which('unsquashfs') == None:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsquashfs program not found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## need at least a header, plus version
        ## see /usr/share/magic
        if filesize - offset < 30:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid squashfs version'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)


        ## The location of the size of the squashfs file system depends on
        ## the major version of the file. These values can be found in /usr/share/magic
        ## or in the squashfs-tools source code ( squashfs_compat.h and squashfs_fs.h )
        if majorversion == 4:
                checkfile.seek(offset+40)
                checkbytes = checkfile.read(8)
                if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data to read size'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if bigendian:
                        squashfssize = int.from_bytes(checkbytes, byteorder='big')
                else:
                        squashfssize = int.from_bytes(checkbytes, byteorder='little')
        elif majorversion == 3:
                checkfile.seek(offset+63)
                checkbytes = checkfile.read(8)
                if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data to read size'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if bigendian:
                        squashfssize = int.from_bytes(checkbytes, byteorder='big')
                else:
                        squashfssize = int.from_bytes(checkbytes, byteorder='little')
        elif majorversion == 2:
                checkfile.seek(offset+8)
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data to read size'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if bigendian:
                        squashfssize = int.from_bytes(checkbytes, byteorder='big')
                else:
                        squashfssize = int.from_bytes(checkbytes, byteorder='little')

        ## file size sanity check
        if offset + squashfssize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'file system cannot extend past file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## then create a temporary file and copy the data into the temporary file
        ## but only if offset != 0
        if offset != 0:
                temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
                ## depending on the variant of squashfs a file size can be determined
                ## meaning less data needs to be copied.
                os.sendfile(temporaryfile[0], checkfile.fileno(), offset, filesize - offset)
                os.fdopen(temporaryfile[0]).close()
        checkfile.close()

        ## unpack in a temporary directory, as unsquashfs expects
        ## to create the directory itself, but the unpacking directory
        ## already exists.
        squashfsunpackdirectory = tempfile.mkdtemp(dir=temporarydirectory)

        if offset != 0:
                p = subprocess.Popen(['unsquashfs', temporaryfile[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=squashfsunpackdirectory)
        else:
                p = subprocess.Popen(['unsquashfs', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=squashfsunpackdirectory)
        (outputmsg, errormsg) = p.communicate()

        if offset != 0:
                os.unlink(temporaryfile[1])

        if p.returncode != 0:
                shutil.rmtree(squashfsunpackdirectory)
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Not a valid squashfs file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                for filename in direntries[1]:
                        fullfilename = os.path.join(direntries[0], filename)
                        if not os.path.islink(fullfilename):
                                os.chmod(fullfilename, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
                        unpackedfilesandlabels.append((fullfilename, []))
                for filename in direntries[2]:
                        fullfilename = os.path.join(direntries[0], filename)
                        unpackedfilesandlabels.append((fullfilename, []))

        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'Not a valid Squashfs'}
        return (True, squashfssize, unpackedfilesandlabels, labels, unpackingerror)

## a wrapper around shutil.copy2 to copy symbolic links instead of
## following them and copying the data. This is used in squashfs unpacking
## amongst others.
def local_copy2(src, dest):
    return shutil.copy2(src, dest, follow_symlinks=False)

## https://tools.ietf.org/html/rfc1740
## file format is described in appendices A & B
## test files: any ZIP file unpacked on MacOS X which
## has a directory called "__MACOSX"
## Files starting with ._ are likely AppleDouble encoded
def unpackAppleDouble(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not a valid Apple Double file'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## then 16 filler bytes, all 0x00
    checkbytes = checkfile.read(16)
    if len(checkbytes) != 16:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough filler bytes'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 16

    ## then the number of entries
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no number of entries'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 2

    ## the number of entries, 0 or more, immediately
    ## following the header
    appledoubleentries = int.from_bytes(checkbytes, byteorder='big')

    ## store maximum offset, because the RFC says:
    ## "The entries in the AppleDouble Header file can appear in any order"
    maxoffset = -1

    for i in range(0,appledoubleentries):
        ## first the entry id, which cannot be 0
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'incomplete entry'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
        if int.from_bytes(checkbytes, byteorder='big') == 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no valid entry id'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## then the offset
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'incomplete entry'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)

        ## offset cannot be outside of the file
        entryoffset = int.from_bytes(checkbytes, byteorder='big')
        if offset + entryoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## then the size
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'incomplete entry'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
        ## data cannot be outside of the file
        entrysize = int.from_bytes(checkbytes, byteorder='big')
        if offset + entryoffset + entrysize> filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4
        maxoffset = max(maxoffset, entrysize + entryoffset)

    ## the entire file is the Apple Double file
    if offset == 0 and maxoffset == filesize:
        checkfile.close()
        labels.append('resource')
        labels.append('appledouble')
        return (True, maxoffset, unpackedfilesandlabels, labels, unpackingerror)

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked-from-appledouble")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, maxoffset)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['appledouble', 'resource', 'unpacked']))
    return (True, maxoffset, unpackedfilesandlabels, labels, unpackingerror)

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
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## ICC.1:2010, section 7.1
    if filesize - offset < 128:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Not a valid ICC file'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Not enough data'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
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
    checkbytes = checkfile.read(4)
    if not checkbytes in [b'scnr', b'mntr', b'prtr', b'link', b'spac', b'abst', b'nmcl']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid profile/device class field'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## data colour space field, ICC.1:2010, 7.2.6
    checkbytes = checkfile.read(4)
    if not checkbytes in [b'XYZ ', b'Lab ', b'Luv ', b'YCbr', b'Yxy ', b'RGB ', b'GRAY', b'HSV ', b'HLS ', b'CMYK', b'CMY ', b'2CLR', b'3CLR', b'4CLR', b'5CLR', b'6CLR', b'7CLR', b'8CLR', b'9CLR', b'ACLR', b'BCLR', b'CCLR', b'DCLR', b'ECLR', b'FCLR']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid profile/device class field'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
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
    if not checkbytes in [b'APPL', b'MSFT', b'SGI ', b'SUNW', b'\x00\x00\x00\x00']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid profile/device class field'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## last 28 bytes of header should be 0x00, ICC.1:2010, 7.2.19
    checkfile.seek(offset+100)
    unpackedsize = 100
    checkbytes = checkfile.read(28)

    if not checkbytes == b'\x00' * 28:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'reserved bytes not \\x00'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)

    ## skip to the tag table, ICC.1:2010, 7.3
    checkfile.seek(offset+128)
    unpackedsize = 128

    ## the first 4 bytes are the tag count, ICC.1:2010 7.3.2
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no tag table'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
    tagcount = int.from_bytes(checkbytes, byteorder='big')
    ## each tag is 12 bytes
    if offset + unpackedsize + 4 + tagcount * 12 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for tag table'}
        return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    maxtagoffset = 0
    for n in range(0,tagcount):
        checkbytes = checkfile.read(12)
        ## first four bytes for a tag are the tag signature, ICC.1:2010 7.3.3
        ## skip for now.

        ## next four bytes are the offset of the data, ICC.1:2010 7.3.4
        icctagoffset = int.from_bytes(checkbytes[4:8], byteorder='big')

        ## tag offset has to be on a 4 byte boundary
        if icctagoffset%4 != 0:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid tag offset'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
        if offset + icctagoffset > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'offset outside of file'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)

        ## then the size of the data, ICC.1:2010 7.3.5
        icctagsize = int.from_bytes(checkbytes[8:12], byteorder='big')
        if offset + icctagoffset + icctagsize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)
        ## add padding if necessary
        if icctagsize % 4 != 0:
            icctagsize += 4 - (icctagsize % 4)
        unpackedsize += 12

        maxtagoffset = max(maxtagoffset, offset + icctagoffset + icctagsize)

        ## the tag offset cannot be outside of the declared profile size
        if maxtagoffset - offset >  profilesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid tag offset'}
            return (False, filesize, unpackedfilesandlabels, labels, unpackingerror)

    if offset == 0 and maxtagoffset == filesize:
        checkfile.close()
        labels.append('icc')
        labels.append('resource')
        return (True, offset+maxtagoffset, unpackedfilesandlabels, labels, unpackingerror)

    ## else carve the file. It is anonymous, so just give it a name
    outfilename = os.path.join(unpackdir, "unpacked.icc")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, maxtagoffset - offset)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['icc', 'resource', 'unpacked']))
    return (True, maxtagoffset-offset, unpackedfilesandlabels, labels, unpackingerror)

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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## the ZIP file format is described in section 4.3.6
        ## the header is at least 30 bytes
        if filesize < 30:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ZIP entry header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ## process everything that is not a local file header, but either
                ## a ZIP header or an Android signing signature.
                if checkbytes != b'\x50\x4b\x03\x04':
                        inlocal = False
                        unpackedsize += 4

                        ## archive decryption header
                        ## archive data extra field (section 4.3.11)
                        if checkbytes == b'\x50\x4b\x06\x08':
                                checkbytes = checkfile.read(4)
                                if len(checkbytes) != 4:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for archive decryption header field'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 4
                                archivedecryptionsize = int.from_bytes(checkbytes, byteorder='little')
                                if checkfile.tell() + archivedecryptionsize > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for archive decryption header field'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                checkfile.seek(archivedecryptionsize, os.SEEK_CUR)
                                unpackedsize += archivedecryptionsize
                        ## check for the start of the central directory (section 4.3.12)
                        elif checkbytes == b'\x50\x4b\x01\02':
                                seencentraldirectory = True
                                if checkfile.tell() + 46 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for end of central directory'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                                ## skip 24 bytes in the header to the file name and extra field
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for file name in central directory'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += filenamelength
                                centraldirectoryfiles.append(checkbytes)

                                if extrafieldlength != 0:
                                        ## read the extra field
                                        checkbytes = checkfile.read(extrafieldlength)
                                        if len(checkbytes) != extrafieldlength:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field in central directory'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        unpackedsize += extrafieldlength

                                if filecommentlength != 0:
                                        ## read the file comment
                                        checkbytes = checkfile.read(filecommentlength)
                                        if len(checkbytes) != filecommentlength:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field in central directory'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        unpackedsize += filecommentlength

                        ## check for digital signatures (section 4.3.13)
                        elif checkbytes == b'\x50\x4b\x05\x05':
                                checkbytes = checkfile.read(2)
                                if len(checkbytes) != 2:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for digital signature size field'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 2
                                digitalsignaturesize = int.from_bytes(checkbytes, byteorder='little')
                                if checkfile.tell() + digitalsignaturesize > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for digital signature'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                checkfile.seek(digitalsignaturesize, os.SEEK_CUR)
                                unpackedsize += digitalsignaturesize

                        ## check for ZIP64 end of central directory (section 4.3.14)
                        elif checkbytes == b'\x50\x4b\x06\x06':
                                if not seencentraldirectory:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'ZIP64 end of cental directory, but no central directory header'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                seenzip64endofcentraldir = True

                                ## first read the size of the ZIP64 end of central directory (section 4.3.14.1)
                                checkbytes = checkfile.read(8)
                                if len(checkbytes) != 8:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ZIP64 end of central directory header'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                                zip64endofcentraldirectorylength = int.from_bytes(checkbytes, byteorder='little')
                                if checkfile.tell() + zip64endofcentraldirectorylength > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ZIP64 end of central directory'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 8

                                ## now skip over the rest of the data in the ZIP64 end of central directory
                                checkfile.seek(zip64endofcentraldirectorylength, os.SEEK_CUR)
                                unpackedsize += zip64endofcentraldirectorylength

                        ## check for ZIP64 end of central directory locator (section 4.3.15)
                        elif checkbytes == b'\x50\x4b\x06\x07':
                                if not seenzip64endofcentraldir:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'ZIP64 end of cental directory locator, but no ZIP64 end of central directory'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                if checkfile.tell() + 16 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ZIP64 end of central directory locator'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                ## skip over the data
                                checkfile.seek(16, os.SEEK_CUR)
                                unpackedsize += 16

                        ## check for of central directory (section 4.3.16)
                        elif checkbytes == b'\x50\x4b\x05\x06':
                                if not seencentraldirectory:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'end of cental directory, but no central directory header'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                                if checkfile.tell() + 18 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for end of central directory header'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field in central directory'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        unpackedsize += zipcommentlength
                                ## end of ZIP file reached, so break out of the loop
                                break
                        elif checkbytes == b'PK\x07\x08':
                                if checkfile.tell() + 12 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for data descriptor'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                checkfile.seek(12,os.SEEK_CUR)
                        else:
                                ## then check to see if this is possibly an Android
                                ## signing block
                                ## https://source.android.com/security/apksigning/v2
                                if androidsigning:
                                        ## first go back four bytes
                                        checkfile.seek(-4, os.SEEK_CUR)
                                        unpackedsize -= 8

                                        ## then read 8 bytes for the APK signing block size
                                        checkbytes = checkfile.read(8)
                                        if len(checkbytes) != 8:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for Android signing block'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        unpackedsize += 8
                                        androidsigningsize = int.from_bytes(checkbytes, byteorder='little')
                                        if checkfile.tell() + androidsigningsize > filesize:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for Android signing block'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                                        ## then skip over the signing block, except the last 16 bytes
                                        ## to have an extra sanity check
                                        checkfile.seek(androidsigningsize - 16, os.SEEK_CUR)
                                        checkbytes = checkfile.read(16)
                                        if checkbytes != b'APK Sig Block 42':
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong magic for Android signing block'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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

                ## minimal version needed. According to 4.4.3.2 the minimal version is
                ## 1.0 and the latest is 6.3. As new versions of PKZIP could be released
                ## this check should not be too strict.
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                minversion = int.from_bytes(checkbytes, byteorder='little')
                if minversion < 10:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid ZIP version'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if minversion > maxzipversion:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid ZIP version'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 2

                ## then the "general purpose bit flag" (section 4.4.4)
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for general bit flag in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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

                ## see if there is a data descriptor for regular files in the general
                ## purpose bit flag (this won't be set for directories)
                if generalbitflag & 0x08 == 0x08:
                        datadescriptor = True

                ## then the compression method (section 4.4.5)
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for compression method in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                compressionmethod = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                ## skip over the time fields (section 4.4.6)
                checkfile.seek(4, os.SEEK_CUR)
                if checkfile.tell() + 4 > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for time fields in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## skip over the CRC32 (section 4.4.7)
                if checkfile.tell() + 4 > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for CRC32 in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                checkfile.seek(4, os.SEEK_CUR)
                unpackedsize += 4

                ## compressed size (section 4.4.8)
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for compressed size in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                compressedsize = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 4

                ## uncompressed size (section 4.4.9)
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for uncompressed size file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                uncompressedsize = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 4

                ## then the file name length (section 4.4.10)
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for filename length in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                filenamelength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2

                ## and the extra field length (section 4.4.11)
                ## There does not necessarily have to be any useful data in
                ## the extra field.
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field length in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                extrafieldlength = int.from_bytes(checkbytes, byteorder='little')

                unpackedsize += 2

                localfilename = checkfile.read(filenamelength)
                if len(localfilename) != filenamelength:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for file name in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                localfiles.append(localfilename)
                unpackedsize += filenamelength

                ## then check the extra field. The most important is to check for any
                ## ZIP64 extension, as it contains updated values for the compressed
                ## size and uncompressed size (section 4.5)
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                if extrafieldheaderid == 0x001:
                                        ## ZIP64, section 4.5.3
                                        ## according to 4.4.3.2 PKZIP 4.5 or later is needed to
                                        ## unpack ZIP64 files.
                                        if minversion < 45:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong minimal needed version for ZIP64'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        zip64uncompressedsize = int.from_bytes(extrafields[extrafieldcounter:extrafieldcounter+8], byteorder='little')
                                        zip64compressedsize = int.from_bytes(extrafields[extrafieldcounter+8:extrafieldcounter+16], byteorder='little')
                                        if compressedsize == 0xffffffff:
                                                compressedsize = zip64compressedsize
                                        if uncompressedsize == 0xffffffff:
                                                uncompressedsize = zip64uncompressedsize
                                extrafieldcounter += extrafieldheaderlength
                        unpackedsize += extrafieldlength

                ## some sanity checks: file name, extra field and compressed size
                ## cannot extend past the file size
                locallength = 30 + filenamelength + extrafieldlength + compressedsize
                if offset + locallength > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'data cannot be outside file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ## keep track if a data descriptor was searched and found
                ## This is needed if the length of the compressed size is set
                ## to 0, which can happen in certain cases (section 4.4.4, bit 3)
                ddfound = False
                ddsearched = False

                if not localfilename.endswith(b'/') and compressedsize == 0:
                        datastart = checkfile.tell()
                        ## in case the length is not known it is very difficult
                        ## to see where the data ends so it is needed to search for
                        ## a signature. This can either be:
                        ## * data descriptor header
                        ## * local file header
                        ## * central directory header
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
                                                                        ## and (again) return to the original position
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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for compressed data'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for compressed data field'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 4
                        checkbytes = checkfile.read(4)
                        if len(checkbytes) != 4:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for uncompressed data field'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        dduncompressedsize = int.from_bytes(checkbytes, byteorder='little')
                        if uncompressedsize != 0:
                                ## possibly do an extra sanity check here with the
                                ## compressed and/or uncompressed size fields
                                pass

        if not seencentraldirectory:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no central directory found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## there should be as many entries in the local headers as in the central directory
        if len(localfiles) != len(centraldirectoryfiles):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'mismatch between local file headers and central directory'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## compute the difference between the local files and the ones in the central directory
        if len(set(localfiles).intersection(set(centraldirectoryfiles))) != len(set(localfiles)):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'mismatch between names in local file headers and central directory'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                        checkfile.close()
                        for i in zipinfolist:
                                unpackedfilesandlabels.append((os.path.join(unpackdir, i.filename), []))
                        if offset == 0 and not carved:
                                labels.append('compressed')
                                labels.append('zip')
                        if carved:
                                os.unlink(temporaryfile[1])
                        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                except zipfile.BadZipFile:
                        if carved:
                                os.unlink(temporaryfile[1])
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'Not a valid ZIP file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## it is an encrypted file
        if offset == 0 and checkfile.tell() == filesize:
                labels.append('compressed')
                labels.append('zip')
                labels.append('encrypted')
                return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file
        targetfilename = os.path.join(unpackdir, 'encrypted.zip')
        targetfile = open(targetfilename, 'wb')
        os.sendfile(targetfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        targetfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((targetfilename, ['encrypted', 'zip', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Derived from public bzip2 specifications
## and Python module documentation
def unpackBzip2(filename, offset, unpackdir, temporarydirectory, dryrun=False):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 10:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'File too small (less than 10 bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
        ## no data could be successfully unpacked, so close the file and exit.
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'File not a valid bzip2 file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## set the name of the file in case it is "anonymous data"
    ## otherwise just imitate whatever bunzip2 does. If the file has a
    ## name recorded in the file it will be renamed later.
    if filename.endswith('.bz2'):
        outfilename = os.path.join(unpackdir, os.path.basename(filename)[:-4])
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
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'File not a valid bzip2 file, use bzip2recover?'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

        if offset == 0 and unpackedsize == os.stat(filename).st_size:
            ## in case the file name ends in either bz2 or tbz2 (tar) rename the file
            ## to mimic the behaviour of "bunzip2"
            if filename.lower().endswith('.bz2'):
                newoutfilename = os.path.join(unpackdir, os.path.basename(filename)[:-4])
                shutil.move(outfilename, newoutfilename)
                outfilename = newoutfilename
            elif filename.lower().endswith('.tbz2'):
                newoutfilename = os.path.join(unpackdir, os.path.basename(filename)[:-5]) + ".tar"
                shutil.move(outfilename, newoutfilename)
                outfilename = newoutfilename
            labels += ['bzip2', 'compressed']
        unpackedfilesandlabels.append((outfilename, []))
    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Derived from specifications at:
## https://github.com/mackyle/xar/wiki/xarformat
##
## Basically XAR is a header, a zlib compressed XML file describing where to find
## files and how they were compressed, and then the actual data (perhaps compressed).
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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}

        if filesize - offset < 28:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'Too small for XAR file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

        ## check that the table of contents (toc) is actually inside the file
        if offset + headersize + toc_length_compressed > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'file too small'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 8

        ## read the toc_length_uncompressed field. Use this for sanity checking.
        checkbytes = checkfile.read(8)
        unpackedsize += 8
        toc_length_uncompressed = int.from_bytes(checkbytes, byteorder='big')

        ## read the cksum_alg field. In case it is 3 do some extra sanity checks.
        checkbytes = checkfile.read(4)
        checksumalgorithm = int.from_bytes(checkbytes, byteorder='big')
        if checksumalgorithm == 3:
                if filesize - offset < 32:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'file too small'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                if headersize < 32:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'header too small'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                if headersize % 4 != 0:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'header not 4 byte aligned'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        else:
                ## all the other checksum algorithms have a 28 byte header
                if headersize != 28:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong header size'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'cannot decompress table of contents'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if len(toc) != toc_length_uncompressed:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table of contents length does not match header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## the toc is an XML file, so parse it
        try:
                tocdom = xml.dom.minidom.parseString(toc)
        except:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table of contents is not valid XML'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## The interesting information is in the <file> element. As these
        ## can be nested (to resemble a directory tree) each element has
        ## to be looked at separately to see if there are any child elements
        ## that have files or other directories.

        ## The top level element should be <xar>
        if tocdom.documentElement.tagName != 'xar':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table of contents is not a valid TOC for XAR'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table of contents is not a valid TOC for XAR'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize += toc_length_compressed

        ## Then further traverse the DOM
        ## Since each element only has relative path information it is necessary to keep track of
        ## the directory structure.

        maxoffset = -1

        ## store the nodes to traverse from the DOM in a deque, and then pop from the
        ## left as it is much more efficient then using a list for that.
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'XML bogus values'}
                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                ## the checksum cannot be outside of the file
                                if offset + unpackedsize + checksumoffset + checksumsize > filesize:
                                        targetfile.close()
                                        os.unlink(targetfilename)
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'missing file type in TOC'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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

                ## remove any superfluous / characters. This should not happen with XAR
                ## but just in case...
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'bogus XML values'}
                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                ## more sanity checks
                                ## the file cannot be outside of the file
                                if offset + unpackedsize + dataoffset + datalength > filesize:
                                        targetfile.close()
                                        os.unlink(targetfilename)
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                checkhash = None

                                ## create a hashing object for the uncompressed file
                                if extractedchecksumtype in hashlib.algorithms_available:
                                        checkhash = hashlib.new(extractedchecksumtype)

                                ## seek to the beginning of the file
                                checkfile.seek(offset+unpackedsize+dataoffset)
                                if compressionmethod == 'none':
                                        ## if no compression is used just write the bytes to the
                                        ## target file immediately.
                                        bytesread = 0
                                        ## write in chunks of 10 MB
                                        maxbytestoread = 10000000
                                        while bytesread != datalength:
                                                checkbytes = checkfile.read(min(maxbytestoread, datalength-bytesread))
                                                targetfile.write(checkbytes)
                                                bytesread += len(checkbytes)
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
                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'compression method not supported'}
                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                bytesread = 0
                                                ## read in chunks of 10 MB
                                                maxbytestoread = 10000000
                                                while bytesread != datalength:
                                                        checkbytes = checkfile.read(min(maxbytestoread, datalength-bytesread))
                                                        ## decompress the data and write it to the target file
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
                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'broken data'}
                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                ## if there is a checksum compare it to the one that was
                                                ## stored in the file.
                                                if checkhash != None:
                                                        if extractedchecksum != checkhash.hexdigest():
                                                                targetfile.close()
                                                                os.unlink(targetfilename)
                                                                checkfile.close()
                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'checksum mismatch'}
                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                        except Exception as e:
                                                targetfile.close()
                                                os.unlink(targetfilename)
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'broken data'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
        if offset == 0 and maxoffset == filesize:
                labels += ['archive', 'xar']
        return (True, maxoffset - offset, unpackedfilesandlabels, labels, unpackingerror)

## GIF unpacker for the GIF87a and GIF89a formats. The specification
## can be found at:
##
## https://www.w3.org/Graphics/GIF/spec-gif89a.txt
##
## The references in the comments correspond to sections in this
## document.
## A grammer for the GIF format is described in Appendix B.
def unpackGIF(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## a minimal GIF file is 6 + 6 + 6 + 1 = 19
        if filesize - offset < 19:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'incompatible terminator records mixed'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid logical screen width'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## then the logical screen height, cannot be 0
        checkbytes = checkfile.read(2)
        logicalscreenheight = int.from_bytes(checkbytes, byteorder='little')
        if logicalscreenheight == 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid logical screen height'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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

        ## skip over the global color table, if there is one (section 19(
        if haveglobalcolortable:
                if offset + unpackedsize + globalcolortablesize > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for global color table'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                checkfile.seek(globalcolortablesize, os.SEEK_CUR)
                unpackedsize += globalcolortablesize

        ## then there are 0 or more data blocks
        ## data blocks are either graphic blocks or special purpose blocks
        ## and are followed by a trailer.

        havegiftrailer = False
        animated = False

        while True:
                checkbytes = checkfile.read(1)
                if len(checkbytes) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for data blocks or trailer'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 1

                ## first check to see if there is a trailer (section 27)
                if checkbytes == b'\x3b':
                        havegiftrailer = True
                        break

                ## The various extensions all start with 0x21 (section 23, 24, 25, 26, appendix C)
                if checkbytes == b'\x21':
                        ## the next byte gives more information about which extension was used
                        checkbytes = checkfile.read(1)
                        if len(checkbytes) != 1:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for data blocks or trailer'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 1
                        ## a graphic block is an optional graphic control extension
                        ## (section 23) followed by a graphic rendering block
                        if checkbytes == b'\xf9':
                                ## then read the next 6 bytes
                                checkbytes = checkfile.read(6)
                                if len(checkbytes) != 6:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for graphic control extension'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                if checkbytes[0] != 4:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for graphic control extension size'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                ## last byte is the block terminator (section 16)
                                if checkbytes[5] != 0:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for graphic control extension block terminator'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for block size'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        unpackedsize += 1

                                        ## check for a block terminator (section 16)
                                        if checkbytes == b'\x00':
                                                break

                                        ## else read the data
                                        datasize = ord(checkbytes)
                                        if offset + unpackedsize + datasize > filesize:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for LZW data bytes'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        gifcomment += checkfile.read(datasize)
                                        unpackedsize += datasize
                        ## process the application extension (section 26)
                        elif checkbytes == b'\xff':
                                checkbytes = checkfile.read(1)
                                if len(checkbytes) != 1:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for block size'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                ## block size describes the application extension header
                                ## and has fixed value 11.
                                if ord(checkbytes) != 11:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for block size'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 1
                                if offset + unpackedsize + 11 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for application extension header'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                                ## The structure rest of the rest of the data depends
                                ## on the application identifier.

                                ## First read the application identifier
                                applicationidentifier = checkfile.read(8)

                                ## and the application authentication code
                                applicationauth = checkfile.read(3)
                                unpackedsize += 11

                                ## Then process the application data for different extensions.
                                ## Only a handful have been defined but only three are in widespread
                                ## use (netscape, icc, xmp).
                                ##
                                ## http://fileformats.archiveteam.org/wiki/GIF#Known_application_extensions
                                if applicationidentifier == b'NETSCAPE' and applicationauth == b'2.0':
                                        ## http://giflib.sourceforge.net/whatsinagif/bits_and_bytes.html#application_extension_block
                                        ## The Netscape extension is for animations.
                                        animated = True
                                        checkbytes = checkfile.read(4)
                                        if len(checkbytes) != 4:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for application data'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        if checkbytes[0] != 3 or checkbytes[1] != 1:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for application data'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        unpackedsize += 4

                                        ## finally a block terminator (section 16)
                                        checkbytes = checkfile.read(1)
                                        if checkbytes != b'\x00':
                                                break
                                        unpackedsize += 1

                                elif applicationidentifier == b'ICCRGBG1' and applicationauth == b'012':
                                        ## ICC profiles, http://www.color.org/icc1V42.pdf, section B.6
                                        iccprofile = b''
                                        while True:
                                                checkbytes = checkfile.read(1)
                                                if len(checkbytes) != 1:
                                                        checkfile.close()
                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for block size'}
                                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                                unpackedsize += 1

                                                ## finally a block terminator (section 16)
                                                if checkbytes == b'\x00':
                                                        break

                                                ## else read the data
                                                datasize = ord(checkbytes)
                                                if offset + unpackedsize + datasize > filesize:
                                                        checkfile.close()
                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ICC data bytes'}
                                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                                iccprofile += checkfile.read(datasize)
                                                unpackedsize += datasize
                                elif applicationidentifier == b'XMP Data' and applicationauth == b'XMP':
                                        ## XMP data
                                        ## https://wwwimages2.adobe.com/content/dam/acom/en/devnet/xmp/pdfs/XMP%20SDK%20Release%20cc-2016-08/XMPSpecificationPart3.pdf
                                        ## broken XMP headers exist, so store the XMP data for a few extra sanity checks.
                                        xmpdata = b''
                                        while True:
                                                checkbytes = checkfile.read(1)
                                                if len(checkbytes) != 1:
                                                        checkfile.close()
                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for block size'}
                                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                                unpackedsize += 1

                                                ## finally a block terminator (section 16)
                                                if checkbytes == b'\x00' and len(xmpdata) >= 258:
                                                        break

                                                xmpdata += checkbytes

                                                ## else read the data
                                                datasize = ord(checkbytes)
                                                if offset + unpackedsize + datasize > filesize:
                                                        checkfile.close()
                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for ICC data bytes'}
                                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                                xmpdata += checkfile.read(datasize)
                                                unpackedsize += datasize
                                        xmpdata = xmpdata[:-257]

                ## process the image descriptor (section 20)
                elif checkbytes == b'\x2c':
                        ## the image descriptor is 10 bytes in total, of which
                        ## 1 has already been read
                        checkbytes = checkfile.read(9)
                        if len(checkbytes) != 9:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for image descriptor'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 9

                        ## images can have a separate color table
                        havelocalcolortable = False
                        if checkbytes[-1] & 0x80 == 0x80:
                                havelocalcolortable = True

                        ## check if there is a local color table (section 21) and if so, skip it
                        if havelocalcolortable:
                                localcolortablesize = pow(2, (ord(checkbytes) & 7) + 1) * 3
                                if offset + unpackedsize + localcolortablesize > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for local color table'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                checkfile.seek(localcolortablesize, os.SEEK_CUR)
                                unpackedsize += localcolortablesize

                        ## then the image data (section 22)
                        ## The first byte describes the LZW minimum code size
                        checkbytes = checkfile.read(1)
                        if len(checkbytes) != 1:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for LZW minimum code size'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 1

                        ## then the raster data stream (appendix F).
                        while True:
                                checkbytes = checkfile.read(1)
                                if len(checkbytes) != 1:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for block size'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 1

                                ## check for a block terminator (section 16)
                                if checkbytes == b'\x00':
                                        break

                                ## else skip over data
                                datasize = ord(checkbytes)
                                if offset + unpackedsize + datasize > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for LZW data bytes'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                checkfile.seek(datasize, os.SEEK_CUR)
                                unpackedsize += datasize
                else:
                        break

        ## if there is no GIF trailer, then the file cannot be valid
        if not havegiftrailer:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'GIF trailer not found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        if offset == 0 and unpackedsize == filesize:
                ## now load the file into PIL as an extra sanity check
                try:
                        testimg = PIL.Image.open(checkfile)
                        testimg.load()
                        testimg.close()
                except:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid GIF data according to PIL'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                checkfile.close()

                labels += ['gif', 'graphics']
                if animated:
                        labels.append('animated')
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid GIF data according to PIL'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        outlabels = ['gif', 'graphics', 'unpacked']
        if animated:
                outlabels.append('animated')
        unpackedfilesandlabels.append((outfilename, outlabels))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        if filesize - offset < 32769:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'File too small (less than 32769 bytes'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize = 0

        ## each sector is 2048 bytes long (ECMA 119, 6.1.2). The first 16 sectors are
        ## reserved for the "system area" (in total 32768 bytes: ECMA 119, 6.2.1)
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
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough bytes for sector'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                ## each volume descriptor has a type and an identifier (ECMA 119, section 8.1)
                if checkbytes[1:6] != b'CD001':
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong identifier'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                volumedescriptoroffset = checkfile.tell()

                ## volume descriptor type (ECMA 119, section 8.1.1)
                ## 0: boot record
                ## 1: primary volume descriptor
                ## 2: supplementary volume descriptor or an enhanced volume descriptor
                ## 3: volume partition descriptor
                ## 255: volume descriptor set terminator
                if checkbytes[0] == 0:
                        ## boot record. There is no additional data here, except that
                        ## there could be a bootloader located here, which could be important
                        ## for license compliance (isolinux and friends), so mark this as a
                        ## bootable CD.
                        isbootable = True
                elif checkbytes[0] == 1:
                        ## primary volume descriptor (PVD)
                        ## ECMA 119, 8.4
                        haveprimary = True

                        ## most fields are stored in both little endian and big endian format
                        ## and should have the same values.
                        if int.from_bytes(checkbytes[80:84], byteorder='little') != int.from_bytes(checkbytes[84:88], byteorder='big'):
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'endian mismatch'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                        ## ECMA 119, 8.4.8
                        volume_space_size = int.from_bytes(checkbytes[80:84], byteorder='little')

                        ## extra sanity check to see if little endian and big endian
                        ## values match.
                        if int.from_bytes(checkbytes[128:130], byteorder='little') != int.from_bytes(checkbytes[130:132], byteorder='big'):
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'endian mismatch'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## ECMA 119, 8.4.12
                        logical_size = int.from_bytes(checkbytes[128:130], byteorder='little')

                        ## sanity check: the ISO image cannot be outside of the file
                        if offset + volume_space_size * logical_size > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'image cannot be outside of file'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## according to https://wiki.osdev.org/ISO_9660 Linux does not
                        ## use the L-path and M-path but the directory entries instead.
                        ## the PVD contains the directory root entry (ECMA 119, 8.4.8)
                        root_directory_entry = checkbytes[156:190]

                        ## the entry is formatted as described in ECMA 119, 9.1
                        len_dr = root_directory_entry[0]

                        ## extent location (ECMA 119, 9.1.3)
                        extent_location = int.from_bytes(root_directory_entry[2:6], byteorder='little')
                        ## sanity check: the ISO image cannot be outside of the file
                        if offset + extent_location * logical_size > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent location cannot be outside file'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## sanity check: the ISO image cannot be outside of the declared size of the file
                        if extent_location * logical_size > volume_space_size * logical_size:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent location cannot be larger than declared size'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## extent size (ECMA 119, 9.1.4)
                        root_directory_extent_length = int.from_bytes(root_directory_entry[10:14], byteorder='little')
                        ## sanity check: the ISO image cannot be outside of the file
                        if offset + extent_location * logical_size + root_directory_extent_length > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent cannot be outside fle'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## sanity check: the ISO image cannot be outside of the declared size of the file
                        if extent_location * logical_size + root_directory_extent_length > volume_space_size * logical_size:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent cannot be outside of declared size'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## file flags (ECMA 119, 9.1.6)
                        if root_directory_entry[25] >> 1 & 1 != 1:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'file flags for directory wrong'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## file name length (ECMA 119, 9.1.10)
                        file_name_length = root_directory_entry[32]
                        extent_filename = root_directory_entry[33:33+file_name_length]

                        ## ECMA 119, 7.6: file name for root directory is 0x00
                        if extent_filename != b'\x00':
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'root file name wrong'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## record which extents correspond to which names. This is
                        ## important for RockRidge relocations.
                        extenttoname = {}
                        extenttoparent = {}

                        ## recursively walk all entries/extents in the directory structure
                        ## Keep these in a deque data structure for quick access
                        ## For each extent to unpack add:
                        ## location of the extent, the size of the extent, location where to unpack, name
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
                        ## bytes need to be skipped by default (IEEE P1281, section 5.3)
                        suspskip = 0

                        ## then process all the extents with directory records. The
                        ## structure is described in ECMA 119, 6.8
                        ## In the extent pointed to by a directory entry all the entries
                        ## are concatenated (ECMA 119, 6.8.1).
                        while len(extents) != 0:
                                (this_extent_location, this_extent_length, this_extent_unpackdir, this_extent_name) = extents.popleft()

                                ## first seek to the right location in the file
                                checkfile.seek(offset + this_extent_location * logical_size)

                                ## store the starting offset of the current extent
                                orig_extent_offset = checkfile.tell()

                                ## a counter of all data that has been read in this extent so far
                                all_extent_offset = 0

                                while checkfile.tell() - orig_extent_offset < this_extent_length:
                                        ## the entry is formatted as described in ECMA 119, 9.1
                                        extent_directory_length = ord(checkfile.read(1))

                                        ## then reset the file pointer
                                        checkfile.seek(-1,os.SEEK_CUR)

                                        ## and store how much data will have been read after processing
                                        ## this directory.
                                        all_extent_offset += extent_directory_length

                                        ## ECMA 119, 6.8.1.1: "each Directory Record shall end in the Logical
                                        ## Sector in which it begins"
                                        ## This means that there could be padding bytes (NUL)
                                        if extent_directory_length == 0:
                                                ## if there is still a logical size block then jump
                                                ## to the start of that next block
                                                all_extent_offset = ((all_extent_offset//logical_size) + 1) * logical_size
                                                checkfile.seek(orig_extent_offset + all_extent_offset)
                                                continue

                                        ## read the directory entry and process according ECMA 119, 9.1
                                        directory_entry = bytearray(extent_directory_length)
                                        checkfile.readinto(directory_entry)

                                        ## extent location (ECMA 119, 9.1.3)
                                        extent_location = int.from_bytes(directory_entry[2:6], byteorder='little')
                                        ## sanity check: the ISO image cannot be outside of the file
                                        if offset + extent_location * logical_size > filesize:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent location cannot be outside file'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                        ## sanity check: the ISO image cannot be outside of the declared size of the file
                                        if extent_location * logical_size > volume_space_size * logical_size:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent location cannot be bigger than declared size'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                        ## extent size (ECMA 119, 9.1.4)
                                        directory_extent_length = int.from_bytes(directory_entry[10:14], byteorder='little')
                                        ## sanity check: the ISO image cannot be outside of the file
                                        if offset + extent_location * logical_size + directory_extent_length > filesize:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent cannot be outside file'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                        ## sanity check: the ISO image cannot be outside of the declared size of the file
                                        if extent_location * logical_size + directory_extent_length > volume_space_size * logical_size:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'extent outside of declared size'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                        ## file name length (ECMA 119, 9.1.10)
                                        file_name_length = directory_entry[32]

                                        ## file name (ECMA 119, 9.1.11)
                                        extent_filename = directory_entry[33:33+file_name_length].decode()

                                        ## Grab the system use field (ECMA 119, 9.1.13) as this is where
                                        ## Rock Ridge and zisofs information lives (IEEE P1282, section 3)
                                        ## First check if there is a padding byte (ECMA 119, 9.1.12)
                                        if file_name_length%2 == 0:
                                                ## extra check: there should be a padding byte (ECMA 119, 9.1.12)
                                                ## if the file name length is even.
                                                if directory_entry[33+file_name_length] != 0:
                                                        checkfile.close()
                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no mandatory padding byte found'}
                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                system_use = directory_entry[33+file_name_length+1:]
                                        else:
                                                system_use = directory_entry[33+file_name_length:]

                                        ## if RockRidge extensions are used place holder files are
                                        ## written when a directory has been moved. These files should
                                        ## not be created, so indicate whether or not a file needs to
                                        ## be created or not.
                                        createfile = True

                                        if len(system_use) != 0:
                                                ## set the offset to the number of bytes that should
                                                ## be skipped for each system use area according to
                                                ## IEEE P1281, section 5.3
                                                suoffset = suspskip

                                                ## add a stub for an alternate name as the could span
                                                ## multiple entries and need to be concatenated.
                                                alternatename = b''
                                                alternatenamecontinue = True
                                                renamecurrentdirectory = False
                                                renameparentdirectory = False

                                                ## add a stub for a symbolic name as the could span
                                                ## multiple entries and need to be concatenated.
                                                symlinktarget = b''
                                                symlinkcontinue = True
                                                symlinknamecontinue = True

                                                ## store if PL was already seen (IEEE P1282, 4.1.5.2)
                                                havepl = False

                                                ## process according to IEEE P1281, section 4
                                                while True:
                                                        if suoffset >= len(system_use) - 2:
                                                                break

                                                        signatureword = system_use[suoffset:suoffset+2]
                                                        sulength = system_use[suoffset+2]
                                                        if sulength>len(system_use):
                                                                checkfile.close()
                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid length in system use field'}
                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                        suversion = system_use[suoffset+3]
                                                        sudata = system_use[suoffset+4:suoffset+4+sulength]

                                                        ## the 'SP' entry can only appear once per directory hierarchy
                                                        ## and has to be the very first entry of the first directory entry
                                                        ## of the first extent (IEEE P1281, section 5.3)
                                                        if signatureword == b'SP':
                                                                if firstextentprocessed:
                                                                        checkfile.close()
                                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'SP used twice in System Use area'}
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                havesusp = True
                                                                suspskip = system_use[suoffset+6]
                                                        else:
                                                                if not havesusp:
                                                                        checkfile.close()
                                                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'SP not first in System Use area'}
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                ## depending on the SUSP word that follows
                                                                ## the contents should be interpreted differently
                                                                if signatureword == b'ST':
                                                                        ## terminator (IEEE P1281, 5.4)
                                                                        break
                                                                elif signatureword == b'RR':
                                                                        ## this signature word is obsolete but still
                                                                        ## frequently (not always!) used to indicate that
                                                                        ## RockRidge is used
                                                                        haverockridge = True
                                                                elif signatureword == b'CE':
                                                                        ## the continuation area
                                                                        continuation_block = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                                                        continuation_offset = int.from_bytes(system_use[suoffset+12:suoffset+16], byteorder='little')
                                                                        continuation_length = int.from_bytes(system_use[suoffset+20:suoffset+24], byteorder='little')

                                                                        ## first check whether or not the continuation
                                                                        ## data is inside the ISO image.
                                                                        if volume_space_size * logical_size < continuation_block * logical_size + continuation_offset + continuation_length:
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid continuation area location or size'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                        ## store the current position in the file
                                                                        oldoffset = checkfile.tell()
                                                                        checkfile.seek(continuation_block * logical_size + continuation_offset)
                                                                        ## continuation_bytes = checkfile.read(continuation_length)
                                                                        ## TODO

                                                                        ## return to the original position in the file
                                                                        checkfile.seek(oldoffset)
                                                                elif signatureword == b'NM' and alternatenamecontinue:
                                                                        ## The alternate name field is described in IEEE P1282, 4.1.4
                                                                        nmflags = system_use[suoffset+4]

                                                                        ## sanity check: only one of the lower bits can be set
                                                                        nmflagtotal = (nmflags & 1) + (nmflags >> 1 & 1) + (nmflags >> 2 & 1)
                                                                        if nmflagtotal > 1:
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid flag combination in alternate name field'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
                                                                        ## This entry is mandatory, so a good indicator
                                                                        ## that RockRidge is used in case there is no
                                                                        ## 'RR' entry.
                                                                        haverockridge = True
                                                                        ## don't process POSIX flags
                                                                        pass
                                                                elif signatureword == b'SL' and symlinkcontinue:
                                                                        ## symbolic links, IEEE P1282, 4.1.3
                                                                        symflags = system_use[suoffset+4]

                                                                        ## sanity check: only one of the lower bits can be set
                                                                        nmflagtotal = (symflags & 1) + (symflags >> 1 & 1) + (symflags >> 2 & 1)
                                                                        if nmflagtotal > 1:
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid flag combination in alternate name field'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                        if sulength - 5 != 0:
                                                                                ## the rest of the data is the component area
                                                                                ## the first byte is a bit field
                                                                                if system_use[suoffset+5] & 1 == 1:
                                                                                        symlinknamecontinue = True
                                                                                else:
                                                                                        symlinknamecontinue = False

                                                                                if system_use[suoffset+5] & 2 == 2:
                                                                                        if symlinknamecontinue:
                                                                                                checkfile.close()
                                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid flag combination in symbolic name field'}
                                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                                        symlinktarget = b'.'
                                                                                elif system_use[suoffset+5] & 4 == 4:
                                                                                        if symlinknamecontinue:
                                                                                                checkfile.close()
                                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid flag combination in symbolic name field'}
                                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                                        symlinktarget = b'..'
                                                                                elif system_use[suoffset+5] & 8 == 8:
                                                                                        if symlinknamecontinue:
                                                                                                checkfile.close()
                                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid flag combination in symbolic name field'}
                                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'declared component area size larger than SUSP'}
                                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                                         sys.stdout.flush()
                                                                                         symlinktarget += system_use[suoffset+7:suoffset+7+componentlength]

                                                                        if symflags & 1 != 1:
                                                                                symlinkcontinue = False
                                                                elif signatureword == b'SF':
                                                                        ## no need to process sparse file as it doesn't
                                                                        ## seem to be supported well in the real world
                                                                        pass
                                                                elif signatureword == b'TF':
                                                                        ## don't process time field
                                                                        pass

                                                                ## the following three signature words are involved
                                                                ## in directory relocations
                                                                elif signatureword == b'CL':
                                                                        ## IEEE P1282, 4.1.5.1 says:
                                                                        ## If an entry is tagged with CL it means that this entry
                                                                        ## is a placeholder file with the same name as the directory
                                                                        ## and that the directory should be moved to this location.
                                                                        location_child = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                                                        if volume_space_size < location_child:
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid directory relocation'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                        ## don't create, simply store
                                                                        createfile = False

                                                                        ## store the directory here
                                                                        extenttomove[location_child] = this_extent_location
                                                                elif signatureword == b'PL':
                                                                        ## IEEE P1282, 4.1.5.2: PL entry is recorded in SUSP field
                                                                        ## for the parent field.
                                                                        ## This value points to the original parent of the file.
                                                                        if extent_filename != '\x01':
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'PL in wrong directory entry'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                        ## IEEE P1282, 4.1.5.2: only one PL entry
                                                                        ## is allowed per directory entry.
                                                                        if havepl:
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'duplicate PL entry'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                        havepl = True

                                                                        ## location cannot be outside of file
                                                                        location_parent = int.from_bytes(system_use[suoffset+4:suoffset+8], byteorder='little')
                                                                        if volume_space_size < location_parent:
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'relocated directory parent outside of file'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                        ## record the original parent for this extent
                                                                        plparent[this_extent_location] = location_parent
                                                                elif signatureword == b'RE':
                                                                        ## IEEE P1282, 4.1.5.3 describes that the directory entry
                                                                        ## that is described is labeled as relocated, so record it
                                                                        ## as such.
                                                                        relocatedextents.add(extent_location)

                                                                ## zisofs extension
                                                                elif signatureword == b'ZF':
                                                                        havezisofs = True
                                                                        ## some sanity checks
                                                                        pz = system_use[suoffset+4:suoffset+6]
                                                                        if pz != b'pz':
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsupported zisofs compression'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                        zisofs_header_div_4 = system_use[suoffset+6]

                                                                        ## Log2 of Block Size, has to be 15, 16 or 17
                                                                        zisofs_header_log = system_use[suoffset+7]
                                                                        if zisofs_header_log not in [15,16,17]:
                                                                                checkfile.close()
                                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsupported zisofs block size log'}
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                        zisofs_uncompressed = int.from_bytes(system_use[suoffset+8:suoffset+12], byteorder='little')
                                                        ## skip all the other signature words
                                                        suoffset += sulength

                                        ## file flags (ECMA 119, 9.1.6)
                                        if directory_entry[25] >> 1 & 1 == 1:
                                                ## directory entry
                                                if extent_filename == '\x00':
                                                        ## Look at the file name. If it is '.. then it is
                                                        ## safe to skip, but do a sanity check to see if
                                                        ## the location matches with the current one.
                                                        if not this_extent_location == extent_location:
                                                                checkfile.close()
                                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Not a valid ISO9660 file system: wrong back reference for . directory'}
                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                elif extent_filename == '\x01':
                                                        ## TODO: extra sanity checks to see if parent matches
                                                        pass
                                                else:
                                                        ## store the name of the parent, for extra sanity checks
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
                                                ## store the name of the parent, for extra sanity checks
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

                                                        ## absolute symlinks can always be created, as can . and ..
                                                        if os.path.isabs(symlinktarget):
                                                                os.symlink(symlinktarget, outfilename)
                                                        elif symlinktarget == '.' or symlinktarget == '..':
                                                                os.symlink(symlinktarget, outfilename)
                                                        else:
                                                                ## first chdir to the directory, then create
                                                                ## the link and go back
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
                                                                        unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'not enough bytes for zisofs header'}
                                                                        checkfile.close()
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                ## first 8 bytes are the zisofs magic
                                                                checkbytes = checkfile.read(8)
                                                                if checkbytes != b'\x37\xe4\x53\x96\xc9\xdB\xd6\x07':
                                                                        unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'wrong magic for zisofs data'}
                                                                        checkfile.close()
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                ## then the uncompressed size. Should be the same as
                                                                ## in the SUSP entry
                                                                checkbytes = checkfile.read(4)
                                                                if int.from_bytes(checkbytes, byteorder='little') != zisofs_uncompressed:
                                                                        unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'mismatch for uncompressed size in zisofs header and SUSP'}
                                                                        checkfile.close()
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                ## then the zisofs header size
                                                                checkbytes = checkfile.read(1)
                                                                if not ord(checkbytes) == zisofs_header_div_4:
                                                                        unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'mismatch between zisofs header and SUSP'}
                                                                        checkfile.close()
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                ## then the zisofs log2(block size)
                                                                checkbytes = checkfile.read(1)
                                                                if not ord(checkbytes) == zisofs_header_log:
                                                                        unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'mismatch between zisofs header and SUSP'}
                                                                        checkfile.close()
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                block_size = pow(2,zisofs_header_log)

                                                                ## then two reserved bytes
                                                                checkbytes = checkfile.read(2)
                                                                if not int.from_bytes(checkbytes, byteorder='little') == 0:
                                                                        unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'wrong value for reserved bytes'}
                                                                        checkfile.close()
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)


                                                                ## then the pointer array
                                                                blockpointers = math.ceil(zisofs_uncompressed/block_size)+1
                                                                blockpointerarray = []
                                                                for b in range(0,blockpointers):
                                                                        checkbytes = checkfile.read(4)
                                                                        if not len(checkbytes) == 4:
                                                                                unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'not enough data for block pointer'}
                                                                                checkfile.close()
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                        blockpointer = int.from_bytes(checkbytes, byteorder='little')
                                                                        if blockpointer > directory_extent_length:
                                                                                unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'block pointer cannot be outside extent'}
                                                                                checkfile.close()
                                                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                                                                        blockpointerarray.append(blockpointer)

                                                                totalwritten = 0
                                                                for b in range(0, len(blockpointerarray) -1):
                                                                        blockpointer = blockpointerarray[b]
                                                                        nextblockpointer = blockpointerarray[b+1]
                                                                        ## in case the two pointers are the same a block of NULs
                                                                        ## should be written. Normally this is blocksize bytes
                                                                        ## unless there are fewer bytes to be left to write. The
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
                                                                        unpackingerror = {'offset': checkfile.tell() - offset, 'fatal': False, 'reason': 'block pointer ends before directory extent'}
                                                                        checkfile.close()
                                                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                                                checkfile.seek(zisofs_oldoffset)
                                                        outfile.close()
                                                        unpackedfilesandlabels.append((outfilename, []))

                                        ## then skip to the (possible) start of the next directory entry.
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'CL/PL entries do not match'}
                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

                        ## finally return to the old offset to read more volume descriptors
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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no primary volume descriptor'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                elif checkbytes[0] > 3 and checkbytes[0] < 255:
                        ## reserved blocks, for future use, have never been
                        ## implemented for ISO9660.
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no primary volume descriptor'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 2048

                if haveterminator:
                        break

        checkfile.close()

        ## there should always be at least one terminator. If not, then it is not
        ## a valid ISO file
        if not haveterminator:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no volume terminator descriptor'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        if offset == 0 and volume_space_size * logical_size == filesize:
                labels += ['iso9660', 'file system']
        return (True, volume_space_size * logical_size, unpackedfilesandlabels, labels, unpackingerror)

## http://www.nongnu.org/lzip/manual/lzip_manual.html#File-format
def unpackLzip(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    if filesize < 26:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## open the file and skip the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then the version number, should be 1
    lzipversion = ord(checkfile.read(1))
    if lzipversion != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsupported lzip version'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 1

    ## then the LZMA dictionary size. The lowest 5 bits are the dictionary
    ## base size.
    checkbytes = checkfile.read(1)
    dictionarybasesize = pow(2, ord(checkbytes) & 31)
    dictionarysize = dictionarybasesize - (int(dictionarybasesize/16)) * (ord(checkbytes) >> 5)
    unpackedsize += 1

    ## create a LZMA decompressor with custom filter, as the data is stored
    ## without LZMA headers. The LZMA properties are hardcoded for lzip,
    ## except the dictionary.
    lzma_lc = 3
    lzma_lp = 0
    lzma_pb = 2

    lzip_filters = [
         {"id": lzma.FILTER_LZMA1, "dict_size": dictionarybasesize, 'lc': lzma_lc, 'lp': lzma_lp, 'pb': lzma_pb},
    ]

    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=lzip_filters)
    if not filename.endswith('.lz'):
        outfilename = os.path.join(unpackdir, "unpacked-from-lzip")
    else:
        outfilename = os.path.join(unpackdir, os.path.basename(filename[:-3]))
    outfile = open(outfilename, 'wb')

    ## while decompressing also compute the CRC of the uncompressed data,
    ## as it is stored after the compressed LZMA data in the file
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
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not valid LZMA data'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for CRC'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    crcstored = int.from_bytes(checkbytes, byteorder='little')
    ## the CRC stored is the CRC of the uncompressed data
    if crcstored != crccomputed:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong CRC'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## then the size of the original uncompressed data
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for original data size'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
    originalsize = int.from_bytes(checkbytes, byteorder='little')
    if originalsize != os.stat(outfilename).st_size:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong original data size'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 8

    ## then the member size
    checkbytes = checkfile.read(8)
    if len(checkbytes) != 8:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for member size'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
    membersize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## the member size has to be the same as the unpacked size
    if membersize != unpackedsize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong member size'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    checkfile.close()
    unpackedfilesandlabels.append((outfilename, []))
    if offset == 0 and unpackedsize == filesize:
        labels.append('compressed')
        labels.append('lzip')

    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        filesize = os.stat(filename).st_size
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
        tablesmiscmarkers = set([b'\xff\xdb', b'\xff\xc4', b'\xff\xcc', b'\xff\xdd', b'\xff\xfe'])

        ## RST0-7
        rstmarkers = set([b'\xff\xd0', b'\xff\xd1', b'\xff\xd2', b'\xff\xd3', b'\xff\xd4',
                         b'\xff\xd5', b'\xff\xd6', b'\xff\xd7'])

        ## JPEG extension markers -- are these actually being used by someone?
        jpegextmarkers = set([b'\xff\xc8', b'\xff\xf0', b'\xff\xf1', b'\xff\xf2', b'\xff\xf3',
                              b'\xff\xf4', b'\xff\xf5', b'\xff\xf6', b'\xff\xf7', b'\xff\xf8',
                              b'\xff\xf9', b'\xff\xfa', b'\xff\xfb', b'\xff\xfc', b'\xff\xfd'])

        ## APP0-n (16 values)
        appmarkers = set([b'\xff\xe0', b'\xff\xe1', b'\xff\xe2', b'\xff\xe3', b'\xff\xe4', b'\xff\xe5',
                         b'\xff\xe6', b'\xff\xe7', b'\xff\xe8', b'\xff\xe9', b'\xff\xea', b'\xff\xeb',
                         b'\xff\xec', b'\xff\xed', b'\xff\xee', b'\xff\xef'])

        ## start of frame markers
        startofframemarkers = set([b'\xff\xc0', b'\xff\xc1', b'\xff\xc2', b'\xff\xc3', b'\xff\xc5',
                                  b'\xff\xc6', b'\xff\xc7', b'\xff\xc9', b'\xff\xca', b'\xff\xcb',
                                  b'\xff\xcd', b'\xff\xce', b'\xff\xcf'])

        ## keep track of whether or not a frame can be restarted
        restart = False
        eofseen = False

        seenmarkers = set()
        while True:
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 2

                if checkbytes in tablesmiscmarkers or checkbytes in appmarkers:
                        marker = checkbytes
                        seenmarkers.add(checkbytes)
                        ## extract the length of the table or app marker.
                        ## this includes the 2 bytes of the length field itself
                        checkbytes = checkfile.read(2)
                        if not len(checkbytes) == 2:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 2
                        misctablelength = int.from_bytes(checkbytes, byteorder='big')
                        if checkfile.tell() + misctablelength - 2 > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table outside of file'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid DQT value'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                tq = pqtq & 15
                                if not tq < 4:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid DQT value'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                ## There *could* be an EOI marker here and it would be a valid JPEG
                ## according to section B.5, although not all markers would be allowed.
                if checkbytes == b'\xff\xd9':
                        if len(seenmarkers) == 0:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no tables present, needed for abbreviated syntax'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        ## according to B.5 DAC and DRI are not allowed in this syntax.
                        if b'\xff\xcc' in seenmarkers or b'\xff\xdd' in seenmarkers:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'DAC and/or DRI not allowed in abbreviated syntax'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        if offset == 0 and unpackedsize == filesize:
                                checkfile.close()
                                labels.append('graphics')
                                labels.append('jpeg')
                                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        ## else carve the file
                        outfilename = os.path.join(unpackdir, "unpacked.jpg")
                        outfile = open(outfilename, 'wb')
                        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
                        outfile.close()
                        unpackedfilesandlabels.append((outfilename, ['graphics', 'jpeg', 'unpacked']))
                        checkfile.close()
                        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ishierarchical = False

        ## there could be a DHP segment here according to section B.3,
        ## but only one in the entire image
        if checkbytes == b'\xff\xde':
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 2
                sectionlength = int.from_bytes(checkbytes, byteorder='big')
                if checkfile.tell() + sectionlength - 2 > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table outside of file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ishierarchical = True

                ## skip over the section
                checkfile.seek(sectionlength-2, os.SEEK_CUR)
                unpackedsize += sectionlength-2

                ## and make sure that there are already a few bytes read
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 2

        ## now there could be multiple frames, starting with optional misc/tables
        ## again.
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 2
                                misctablelength = int.from_bytes(checkbytes, byteorder='big')
                                if checkfile.tell() + misctablelength - 2 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table outside of file'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 2
                        else:
                                break

                ## check if this is EXP (only in hierarchical syntax)
                if checkbytes == b'\xff\xdf':
                        if not ishierarchical:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'EXP only allowed in hierarchical syntax'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        checkbytes = checkfile.read(2)
                        if not len(checkbytes) == 2:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 2
                        misctablelength = int.from_bytes(checkbytes, byteorder='big')
                        if checkfile.tell() + misctablelength - 2 > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table outside of file'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        ## skip over the section
                        checkfile.seek(misctablelength-2, os.SEEK_CUR)
                        unpackedsize += misctablelength-2

                        ## and read the next two bytes
                        checkbytes = checkfile.read(2)
                        if not len(checkbytes) == 2:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 2

                ## after the tables/misc and possibly EXP there should be
                ## a frame header (B.2.2) with a SOF (start of frame) marker
                if checkbytes in startofframemarkers:

                        ## extract the length of the frame
                        ## this includes the 2 bytes of the length field itself
                        checkbytes = checkfile.read(2)
                        if not len(checkbytes) == 2:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 2
                        misctablelength = int.from_bytes(checkbytes, byteorder='big')
                        if checkfile.tell() + misctablelength - 2 > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table outside of file'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        ## skip over the section
                        checkfile.seek(misctablelength-2, os.SEEK_CUR)
                        unpackedsize += misctablelength-2
                else:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for start of frame'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ## This is followed by at least one scan header, optionally preceded by more tables/misc
                while True:
                        if eofseen:
                                break
                        ## optionally preceded by more tables/misc
                        while True:
                                checkbytes = checkfile.read(2)
                                if not len(checkbytes) == 2:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 2

                                if checkbytes in tablesmiscmarkers or checkbytes in appmarkers:
                                        ## extract the length of the table or app marker.
                                        ## this includes the 2 bytes of the length field itself
                                        checkbytes = checkfile.read(2)
                                        if not len(checkbytes) == 2:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                        unpackedsize += 2
                                        misctablelength = int.from_bytes(checkbytes, byteorder='big')
                                        if checkfile.tell() + misctablelength - 2 > filesize:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table outside of file'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 2

                                headerlength = int.from_bytes(checkbytes, byteorder='big')
                                if checkfile.tell() + headerlength - 2 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'start of scan outside of file'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                ## skip over the section
                                checkfile.seek(headerlength-3, os.SEEK_CUR)
                                unpackedsize += headerlength - 3

                                ## and read two bytes
                                checkbytes = checkfile.read(2)
                                if not len(checkbytes) == 2:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 2

                        ## the SOS (start of scan) header
                        if checkbytes == b'\xff\xda':
                                ## extract the length of the start of scan header
                                ## this includes the 2 bytes of the length field itself
                                checkbytes = checkfile.read(2)
                                if not len(checkbytes) == 2:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table/misc length field'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 2

                                headerlength = int.from_bytes(checkbytes, byteorder='big')
                                if checkfile.tell() + headerlength - 2 > filesize:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'start of scan outside of file'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                                ## the number of image components, can only be 1-4
                                checkbytes = checkfile.read(1)
                                numberimagecomponents = ord(checkbytes)
                                if numberimagecomponents not in [1,2,3,4]:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for number of image components'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                unpackedsize += 1

                                ## the header length = 6+2* number of image components
                                if headerlength != 6+2*numberimagecomponents:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for number of image components or start of scan header length'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                                ## skip over the section
                                checkfile.seek(headerlength-3, os.SEEK_CUR)
                                unpackedsize += headerlength - 3
                        else:
                                if not isrestart:
                                        checkfile.close()
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for start of scan'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid JPEG data according to PIL'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                checkfile.close()

                labels.append('graphics')
                labels.append('jpeg')
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid JPEG data according to PIL'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        unpackedfilesandlabels.append((outfilename, ['jpeg', 'graphics', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Derived from specifications at:
## https://www.w3.org/TR/WOFF/
## section 3 and 4 describe the format
def unpackWOFF(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for font flavour'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## next 4 bytes are the size of the font.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for font size'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## the font cannot be outside of the file
        fontsize = int.from_bytes(checkbytes, byteorder='big')
        if offset + fontsize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'declared font size outside file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## next the number of tables
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for number of tables'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2
        numtables = int.from_bytes(checkbytes, byteorder='big')

        ## next a reserved field. Should be set to 0
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for reserved field'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        if int.from_bytes(checkbytes, byteorder='big') != 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'reserved field not 0'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## next the totalSfntSize. This field must be divisible by 4.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for totalSfntSize'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        if int.from_bytes(checkbytes, byteorder='big')%4 != 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not aligned on 4 byte boundary'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## then the major version
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for major version'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## and the minor version
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for minor version'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## the location of the meta data block. This offset cannot be
        ## outside the file.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for meta data block location'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        metaoffset = int.from_bytes(checkbytes, byteorder='big')
        if offset + metaoffset > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'meta data block cannot be outside of file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        ## the private data block MUST started on a 4 byte boundary (section 7)
        if metaoffset % 4 != 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'meta data doesn\'t start on 4 byte boundary'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## the length of the compressed meta data block. This cannot be
        ## outside the file.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for compressed meta data block'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        metalength = int.from_bytes(checkbytes, byteorder='big')
        if offset + metaoffset + metalength > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'meta data block end outside file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## then the original length of the meta data. Ignore for now.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for original meta data length'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## the location of the private data block. This offset cannot be
        ## outside the file.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for private data block location'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        privateoffset = int.from_bytes(checkbytes, byteorder='big')
        if offset + privateoffset > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'private data block cannot be outside of file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        ## the private data block MUST started on a 4 byte boundary (section 8)
        if privateoffset % 4 != 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'private data block doesn\'t start on 4 byte boundary'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## the length of the private data block. This cannot be outside the file.
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for private data block'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        privatelength = int.from_bytes(checkbytes, byteorder='big')
        if offset + privateoffset + privatelength > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'private data block cannot be outside of file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## then the "table directory"
        lastseenoffset = 0
        for t in range(0,numtables):
                ## the tag of the table
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for tag table'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## the offset of the table. This cannot be outside of the file.
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for table offset'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                tableoffset = int.from_bytes(checkbytes, byteorder='big')
                if offset + tableoffset > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'table offset cannot be outside of file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## then the length of the compressed data, excluding padding
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for compressed table length'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                tablecompressedlength = int.from_bytes(checkbytes, byteorder='big')
                if offset + tableoffset + tablecompressedlength > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'compressed data cannot be outside of file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## then the length of the uncompressed data, excluding padding.
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for uncompressed table length'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                tableuncompressedlength = int.from_bytes(checkbytes, byteorder='big')
                unpackedsize += 4

                ## then the checksum of the uncompressed data. Can be ignored for now
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for uncompressed data checksum'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                                unpackingerror = {'offset': offset+tableoffset, 'fatal': False, 'reason': 'invalid compressed data in font'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        checkfile.seek(offset+tableoffset)

                        ## then return to the previous offset
                        checkfile.seek(prevoffset)

                ## store the last valid offset seen. Fonts don't need to appear in order.
                ## in the font table.
                lastseenoffset = max(lastseenoffset, offset + tableoffset + tablecompressedlength)

        ## set the unpackedsize to the maximum of the last seen offset and the unpacked size.
        ## This is done in case the font table is empty.
        unpackedsize = max(lastseenoffset, unpackedsize) - offset

        ## the declared fontsize cannot be smaller than what was unpacked
        if unpackedsize > fontsize:
                checkfile.close()
                unpackingerror = {'offset': offset+tableoffset, 'fatal': False, 'reason': 'size of unpacked data larger than declared font size'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## it could be that there is padding. There should be a maximum
        ## of three bytes for padding.
        if fontsize - unpackedsize > 3:
                checkfile.close()
                unpackingerror = {'offset': offset+tableoffset, 'fatal': False, 'reason': 'declared font size too large for unpacked data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize = fontsize

        if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels += ['woff', 'font', 'resource']
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file. It is anonymous, so just give it a name
        outfilename = os.path.join(unpackdir, "unpacked-woff")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((outfilename, ['woff', 'font', 'resource', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## a generic method for unpacking fonts:
##
## * TTF
## * OTF
##
## These fonts have a similar structure, but differ in the magic
## header and the required tables.
def unpackFont(filename, offset, unpackdir, temporarydirectory, requiredtables, fontextension, fonttype):
        filesize = os.stat(filename).st_size
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no tables defined'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## followed by the searchRange
        checkbytes = checkfile.read(2)
        searchrange = int.from_bytes(checkbytes, byteorder='big')

        ## the search range is defined as (maximum power of 2 <= numTables)*16
        if pow(2, int(math.log2(numtables)))*16 != searchrange:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'number of tables does not correspond to search range'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## then the entryselector, which is defined as log2(maximum power of 2 <= numTables)
        checkbytes = checkfile.read(2)
        entryselector = int.from_bytes(checkbytes, byteorder='big')
        if int(math.log2(numtables)) != entryselector:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'number of tables does not correspond to entrySelector'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## then the rangeshift
        checkbytes = checkfile.read(2)
        rangeshift = int.from_bytes(checkbytes, byteorder='big')
        if rangeshift != numtables * 16 - searchrange:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'rangeshift does not correspond to rest of header'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2
        tablesseen = set()

        maxoffset = -1

        tablenametooffset = {}

        ## There are fonts that are not 4 byte aligned. Computing checksums for
        ## these is more difficult, as it is unclear whether or not padding should
        ## be added or not.
        ## https://lists.w3.org/Archives/Public/public-webfonts-wg/2010Jun/0063.html
        ##
        ## For the checksums in individual tables it is imperative to add
        ## a few "virtual NUL bytes" to make sure that the checksum can be computed
        ## correctly. However, this doesn't seem to be working for the
        ## checkSumAdjustment value.

        addbytes = 0
        fontname = ''

        ## then read the table directory, with one entry per table
        for i in range(0,numtables):
                ## first the table name
                tablename = checkfile.read(4)
                if len(tablename) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table name'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ## each table can only appear once
                if tablename in tablesseen:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'duplicate table name'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4
                tablesseen.add(tablename)

                ## store the checksum for this table to check later
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table checksum'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4
                tablechecksum = int.from_bytes(checkbytes, byteorder='big')

                ## then the offset to the actual data
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table offset'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4
                tableoffset = int.from_bytes(checkbytes, byteorder='big')

                ## store where the data for each table starts
                tablenametooffset[tablename] = tableoffset

                ## then the length of the data
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table length'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                tablelength = int.from_bytes(checkbytes, byteorder='big')
                unpackedsize += 4

                if offset + tableoffset + tablelength > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ## then compute the checksum for the table
                ## First store the old offset, so it is possible
                ## to return.
                oldoffset = checkfile.tell()
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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for table'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ## parse the name table to see if there is a font name
                ## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6name.html
                if tablename == b'name':
                        localoffset = 0
                        if len(checkbytes) < 6:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data in name table'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        ## first the format selector ("set to 0"). Skip.
                        ## then the name count to indicate how many name records (12 bytes
                        ## each) are present in the name table
                        namecount = int.from_bytes(checkbytes[2:4], byteorder='big')
                        if len(checkbytes) < 6 + namecount * 12:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data in name table'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        ## then the offset of the name table strings
                        nametablestringoffset = int.from_bytes(checkbytes[4:6], byteorder='big')
                        if len(checkbytes) < 6 + namecount * 12 + nametablestringoffset:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data in name table'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'checksum for table incorrect'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                else:
                        ## the head table checksum is different and uses a checksum adjustment,
                        ## which is documented here:
                        ## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6head.html
                        ## First seek to the start of the table and then skip 8 bytes
                        checkfile.seek(offset + tableoffset + 8)
                        checkbytes = checkfile.read(4)
                        checksumadjustment = int.from_bytes(checkbytes, byteorder='big')

                ## then store the maxoffset, including padding, but minus any "virtual" bytes
                if bytesadded:
                        maxoffset = max(maxoffset, offset + tableoffset + tablelength + padding - addbytes)
                else:
                        maxoffset = max(maxoffset, offset + tableoffset + tablelength + padding)

                ## and return to the old offset for the next entry
                checkfile.seek(oldoffset)

        ## first check if all the required tables are there.
        if not tablesseen.intersection(requiredtables) == requiredtables:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not all required tables present'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize = maxoffset - offset

        ## now compute the checksum for the whole font. It is important that checkSumAdjustment
        ## is set to 0 during this computation.
        ## It should be noted that for some fonts (where padding was added to the last table)
        ## this computation might be wrong.
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
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'checksum adjustment does not match computed value'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels.append('font')
                labels.append('resource')
                labels.append(fonttype)
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html
def unpackTrueTypeFont(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## font header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not a valid font file'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## https://developer.apple.com/fonts/TrueType-Reference-Manual/RM06/Chap6.html (table 2)
    ## the following tables are required in a font:
    requiredtables = set([b'cmap', b'glyf', b'head', b'hhea', b'hmtx', b'loca', b'maxp', b'name', b'post'])

    return unpackFont(filename, offset, unpackdir, temporarydirectory, requiredtables, 'ttf', 'TrueType')

## https://docs.microsoft.com/en-us/typography/opentype/spec/otff
def unpackOpenTypeFont(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## font header is at least 12 bytes
    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not a valid font file'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## https://docs.microsoft.com/en-us/typography/opentype/spec/otff (section 'Font Tables')
    ## the following tables are required in a font:
    requiredtables = set([b'cmap', b'head', b'hhea', b'hmtx', b'maxp', b'name', b'OS/2', b'post'])

    return unpackFont(filename, offset, unpackdir, temporarydirectory, requiredtables, 'otf', 'OpenType')

## method to see if a file is a Vim swap file
## These always start with a certain header, including a page size.
##
## struct block0 in memline.c (Vim source code) describes the on disk format
## Various other structs (data block, pointer block) are also described
## in this file.
def unpackVimSwapfile(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    checkfile = open(filename, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(6)
    if len(checkbytes) != 6:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
    if checkbytes != b'b0VIM\x20':
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not a valid Vim swap file header'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    checkfile.seek(12)
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for page size'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    pagesize = int.from_bytes(checkbytes, byteorder='little')

    ## TODO: enable carving.
    if filesize % pagesize != 0:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not a valid Vim swap file'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## then step through the blocks and check the first two
    ## characters of each block. There are two types of blocks: data
    ## blocks and pointer blocks.
    for i in range(1,filesize//pagesize):
        checkfile.seek(i*pagesize)
        checkbytes = checkfile.read(2)
        if not checkbytes in [b'tp', b'ad']:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not a valid Vim swap file block identifier'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## else consider it a Vim swap file
    labels.append('binary')
    labels.append('vim swap')
    return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

## Some firmware updates are distributed as sparse data images. Given a data image and
## a transfer list data on an Android device is block wise added, replaced, erased, or
## zeroed.
##
## The Android sparse data image format is documented in the Android source code tree:
##
## https://android.googlesource.com/platform/bootable/recovery/+/master/updater/blockimg.cpp#1838
##
## Test files can be downloaded from LineageOS, for example:
##
## lineage-14.1-20180410-nightly-FP2-signed.zip
##
## Note: this is different to the Android sparse image format.
def unpackAndroidSparseData(filename, offset, unpackdir, temporarydirectory):

        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}

        ## for each .new.dat file there has to be a corresponding
        ## .transfer.list file as well.
        if not os.path.exists(filename[:-8] + ".transfer.list"):
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'transfer list not found'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## open the transfer list in text mode, not in binary mode
        transferlist = open(filename[:-8] + ".transfer.list", 'r')
        transferlistlines = list(map(lambda x: x.strip(), transferlist.readlines()))
        transferlist.close()

        if len(transferlistlines) < 4:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough entries in transer list'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize = 0

        ## first line is the version number, see comment here:
        ## https://android.googlesource.com/platform/bootable/recovery/+/master/updater/blockimg.cpp#1628
        try:
                versionnumber = int(transferlistlines[0])
        except:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid transfer list version number'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        if versionnumber != 4:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'only transfer list version 4 supported'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## the next line is the amount of blocks (1 block is 4096 bytes)
        ## that will be copied to the output. This does not necessarily anything
        ## about the size of the output file as it might not include the blocks such
        ## as erase or zero, so it can be safely ignored.
        try:
                outputblocks = int(transferlistlines[1])
        except:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid number for blocks to be written'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## then two lines related to stash entries which are only used by Android
        ## during updates to prevent flash space from overflowing, so can safely
        ## be ignored here.
        try:
                stashneeded = int(transferlistlines[2])
        except:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid number for simultaneous stash entries needed'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        try:
                maxstash = int(transferlistlines[2])
        except:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid number for maximum stash entries'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## a list of commands recognized
        validtransfercommands = set(['new', 'zero', 'erase', 'free', 'stash'])

        transfercommands = []

        ## store the maximum block number
        maxblock = 0

        ## then parse the rest of the lines to see if they are valid
        for l in transferlistlines[4:]:
                transfersplit = l.split(' ')
                if len(transfersplit) != 2:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid line in transfer list'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                (transfercommand, transferblocks) = transfersplit
                if not transfercommand in validtransfercommands:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'unsupported command in transfer list'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                transferblockssplit = transferblocks.split(',')
                if len(transferblockssplit)%2 == 0:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid transfer block list in transfer list'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                ## first entry is the number of blocks on the rest of line
                try:
                        transferblockcount = int(transferblockssplit[0])
                except:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid transfer block list in transfer list'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                if not transferblockcount == len(transferblockssplit[1:]):
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid transfer block list in transfer list'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                ## then check the rest of the numbers
                try:
                        blocks = []
                        for b in transferblockssplit[1:]:
                                blocknr = int(b)
                                blocks.append(blocknr)
                                maxblock = max(maxblock, blocknr)
                except:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid transfer block list in transfer list'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                ## store the transfer commands
                transfercommands.append((transfercommand, blocks))

        ## block size is set to 4096 in the Android source code
        blocksize = 4096

        ## cut the extension '.new.dat' from the file name unless the file
        ## name is the extension (as there would be a zero length name).
        if len(os.path.basename(filename[:-8])) == 0:
                outputfilename = os.path.join(unpackdir, "unpacked-from-android-sparse-data")
        else:
                outputfilename = os.path.join(unpackdir, os.path.basename(filename[:-8]))

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

        ## then process all the commands. "zero" is not interesting has the
        ## while underlying file has already been zero filled.
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

        labels += ['androidsparsedata']
        unpackedfilesandlabels.append((outputfilename, []))
        return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)


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
    filesize = os.stat(filename).st_size
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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    if checkbytes != b'1\n':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsupported Android backup version'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 2

    ## Then read the compression flag.
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    if checkbytes != b'1\n':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unsupported Android backup version'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 2

    ## Then read the encryption flag. Only "none" is supported, so read 5 bytes (including newline)
    checkbytes = checkfile.read(5)
    if len(checkbytes) != 5:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    if checkbytes != b'none\n':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'decryption not supported'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid compression'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    os.fdopen(tempbackupfile[0]).close()
    checkfile.close()

    tarfilesize = os.stat(tempbackupfile[1]).st_size

    ## now unpack the tar ball
    tarresult = unpackTar(tempbackupfile[1], 0, unpackdir, temporarydirectory)

    ## cleanup
    os.unlink(tempbackupfile[1])
    if not tarresult[0]:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'corrupt tar inside Android backup file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    if not tarfilesize == tarresult[1]:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'corrupt tar inside Android backup file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## add the labels and pass on the results from the tar unpacking
    labels.append('android backup')
    return (True, unpackedsize, copy.deepcopy(tarresult[2]), labels, unpackingerror)

## https://en.wikipedia.org/wiki/ICO_%28file_format%29
def unpackICO(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## header is 6 bytes
        if offset + 6 > filesize:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for ICO header'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'no images defined'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## each ICONDIRENTRY in the ICONDIR is 16 bytes
        if offset + unpackedsize + numberofimages*16 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for ICONDIR entries'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'wrong size for image data'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## then read the offset of the data
                checkbytes = checkfile.read(4)
                imageoffset = int.from_bytes(checkbytes, byteorder='little')

                ## image cannot be outside of the file
                if offset + imageoffset + imagesize > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'image outside of file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                ## offset cannot be inside the header
                if imageoffset < checkfile.tell() - offset:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'wrong offset for image data'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                        icondir[iconcounter] = {'type': 'png', 'offset': imageoffset, 'size': imagesize, 'width': imagewidth, 'height': imageheight}
                else:
                        ## the file is a BMP
                        ## check the DIB header
                        dibheadersize = int.from_bytes(checkbytes[:2], byteorder='little')
                        if not dibheadersize in set([12, 64, 16, 40, 52, 56, 108, 124]):
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid DIB header size'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        icondir[iconcounter] = {'type': 'bmp', 'offset': imageoffset, 'size': imagesize, 'width': imagewidth, 'height': imageheight}

                ## finally return to the old offset
                checkfile.seek(oldoffset)
                iconcounter += 1

        unpackedsize = maxoffset - offset

        if offset == 0 and unpackedsize == filesize:
                labels.append('graphics')
                labels.append('ico')
                labels.append('resource')
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file
        outfilename = os.path.join(unpackdir, "unpacked.ico")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()

        unpackedfilesandlabels.append((outfilename, ['ico', 'graphics', 'resource', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Chrome PAK
## http://dev.chromium.org/developers/design-documents/linuxresourcesandlocalizedstrings (version 4)
## https://chromium.googlesource.com/chromium/src/tools/grit/+/master/grit/format/data_pack.py (version 5)
def unpackChromePak(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## minimum for version 4: version + number of resources + encoding +  2 zero bytes + end of last file = 15
        ## minimum for version 5: version + encoding + 3 padding bytes + number of resources + number of aliases = 12
        if filesize < 12:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'file too small'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        checkfile = open(filename, 'rb')
        checkfile.seek(offset)

        ## first the version number
        checkbytes = checkfile.read(4)
        pakversion = int.from_bytes(checkbytes, byteorder='little')
        if pakversion != 4 and pakversion != 5:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'unsupported .pak version (can only process version 4 or 5)'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for resource id'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 2

                        checkbytes = checkfile.read(4)
                        if len(checkbytes) != 4:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for resource offset'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        resourceoffset = int.from_bytes(checkbytes, byteorder='little')
                        if resourceoffset + offset > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'resource offset outside file'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 4

                ## two zero bytes
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for zero bytes'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if checkbytes != b'\x00\x00':
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'incorrect value for zero bytes'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 2

                ## the "end of file" value
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for end of file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                endoffile = int.from_bytes(checkbytes, byteorder='little')

                if endoffile + offset > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'end of file cannot be outside of file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for resource id'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 2

                        checkbytes = checkfile.read(4)
                        if len(checkbytes) != 4:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for resource offset'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        resourceoffset = int.from_bytes(checkbytes, byteorder='little')
                        if resourceoffset + offset > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'resource offset outside file'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 4

                ## extra entry at the end with the end of file
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for resource id'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 2
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for end of file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                endoffile = int.from_bytes(checkbytes, byteorder='little')

                ## then all the aliases
                for p in range(0, paknumberofaliases):
                        ## resource id
                        checkbytes = checkfile.read(2)
                        if len(checkbytes) != 2:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for resource id'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 2

                        checkbytes = checkfile.read(2)
                        if len(checkbytes) != 2:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for resource offset'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        aliasresourceoffset = int.from_bytes(checkbytes, byteorder='little')
                        if aliasresourceoffset + offset > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'resource offset outside file'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        unpackedsize += 4

        if endoffile + offset == filesize:
                checkfile.close()
                labels.append('binary')
                labels.append('resource')
                labels.append('pak')
                return (True, endoffile - offset, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file
        outfilename = os.path.join(unpackdir, "unpacked-from-pak")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, endoffile - offset)
        outfile.close()
        unpackedfilesandlabels.append((outfilename, ['binary', 'resource', 'pak', 'unpacked']))
        checkfile.close()

        labels.append('binary')
        return (True, endoffile - offset, unpackedfilesandlabels, labels, unpackingerror)

## The on disk format for GNU message catalog files is described here:
## https://www.gnu.org/software/gettext/manual/gettext.html#index-file-format_002c-_002emo
##
## The extension for these files is often '.mo'
def unpackGNUMessageCatalog(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## header has at least 20 bytes
        if filesize - offset < 20:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for GNU message catalog header'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unknown GNU message catalog version number'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for start of original texts'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for start of original texts'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                        unpackingerror = {'offset': offset+textoffsets, 'fatal': False, 'reason': 'not enough data for message entry'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                if bigendian:
                        ## not sure if this is correct
                        (messagelength, messageoffset) = struct.unpack('>II', checkbytes)
                else:
                        (messagelength, messageoffset) = struct.unpack('<II', checkbytes)

                ## end of the original string cannot be outside of the file
                if offset + messageoffset + messagelength > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+textoffsets, 'fatal': False, 'reason': 'not enough data for message entry'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                maxoffset = max(maxoffset, checkfile.tell(), offset + messageoffset + messagelength)

                ## then the location of the translation
                checkfile.seek(offset+translationoffsets+i*8)
                checkbytes = checkfile.read(8)
                if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+textoffsets, 'fatal': False, 'reason': 'not enough data for message entry'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if bigendian:
                        (messagelength, messageoffset) = struct.unpack('>II', checkbytes)
                else:
                        (messagelength, messageoffset) = struct.unpack('<II', checkbytes)

                ## end of the translated string cannot be outside of the file
                if offset + messageoffset + messagelength > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+textoffsets, 'fatal': False, 'reason': 'not enough data for message entry'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                checkfile.seek(offset+messageoffset)
                checkbytes = checkfile.read(messagelength)

                ## is it NUL terminated? If not read an extra byte and check if it is NUL
                if not checkbytes[-1] == b'\x00':
                        checkbytes = checkfile.read(1)
                        if checkbytes != b'\x00':
                                checkfile.close()
                                unpackingerror = {'offset': offset+textoffsets, 'fatal': False, 'reason': 'entry not NUL terminated'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                maxoffset = max(maxoffset, checkfile.tell())

        unpackedsize = checkfile.tell() - offset

        ## see if the whole file is a GNU message catalog
        if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels.append('binary')
                labels.append('resource')
                labels.append('GNU message catalog')
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file
        outfilename = os.path.join(unpackdir, "unpacked-from-message-catalog")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        unpackedfilesandlabels.append((outfilename, ['binary', 'resource', 'GNU message catalog', 'unpacked']))
        checkfile.close()
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://en.wikipedia.org/wiki/Cabinet_(file_format)
##
## Microsoft has documented the file format here:
##
## https://msdn.microsoft.com/en-us/library/bb267310.aspx#struct_spec
##
## but is currently not under the open specification promise
def unpackCab(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## there are 33 bytes for all mandatory cab headers
    if filesize < 33:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## open the file and skip the magic and reserved field
    checkfile = open(filename, 'rb')
    checkfile.seek(offset+8)
    unpackedsize += 8

    ## check the filesize
    checkbytes = checkfile.read(4)
    cabinetsize = int.from_bytes(checkbytes, byteorder='little')
    if cabinetsize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'defined cabinet size larger than file'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    if shutil.which('cabextract') == None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'cabextract program not found'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid cab file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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

    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## SGI file format
## https://media.xiph.org/svt/SGIIMAGESPEC
def unpackSGI(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        if filesize - offset < 512:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for SGI header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        checkfile = open(filename, 'rb')
        ## skip over the magic
        checkfile.seek(offset+2)
        unpackedsize += 2

        ## next the storage byte
        checkbytes = checkfile.read(1)
        if not (ord(checkbytes) == 0 or ord(checkbytes) == 1):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for storage format'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for BPC'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 1

        ## next the dimensions. The only allowed values are 1, 2, 3
        checkbytes = checkfile.read(2)
        dimensions = int.from_bytes(checkbytes, byteorder='big')
        if not dimensions in [1,2,3]:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for dimensions'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for dummy bytes in header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for colormap'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## last 404 bytes of the header should be 0x00
        checkfile.seek(offset+108)
        checkbytes = checkfile.read(404)
        if checkbytes != b'\x00' * 404:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for dummy bytes in header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 404

        if storageformat == 'verbatim':
                ## if storage format is verbatim then an image basically
                ## header + (width + height + depth * bytes per pixel)
                imagelength = 512 + xsize * ysize * zsize * bytesperpixel
                if imagelength > filesize - offset:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough image data'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                ## check if the entire file is the image
                if offset == 0 and imagelength == filesize:
                        checkfile.close()
                        labels.append('sgi')
                        labels.append('graphics')
                        return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackedfilesandlabels.append((outfilename, ['sgi', 'graphics', 'unpacked']))
                return (True, imagelength, unpackedfilesandlabels, labels, unpackingerror)

        ## now unpack the LRE format
        ## There should be two tables: starttab and lengthtab
        ## store the table with offsets
        starttab = {}
        for n in range(0,ysize*zsize):
                checkbytes = checkfile.read(4)
                if not len(checkbytes) == 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for RLE start table'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                starttabentry = int.from_bytes(checkbytes, byteorder='big')
                starttab[n] = starttabentry
                unpackedsize += 4

        maxoffset = 0
        for n in range(0,ysize*zsize):
                checkbytes = checkfile.read(4)
                if not len(checkbytes) == 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for RLE length table'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                lengthtabentry = int.from_bytes(checkbytes, byteorder='big')

                ## check if the data is outside of the file
                if offset + starttab[n] + lengthtabentry > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for RLE data'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                maxoffset = max(maxoffset, starttab[n] + lengthtabentry)
                unpackedsize += 4

        unpackedsize = maxoffset

        if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels.append('sgi')
                labels.append('graphics')
                return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

        ## Carve the image.
        ## first reset the file pointer
        checkfile.seek(offset)
        outfilename = os.path.join(unpackdir, "unpacked.sgi")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((outfilename, ['sgi', 'graphics', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Derived from specifications linked at:
## https://en.wikipedia.org/wiki/Audio_Interchange_File_Format
##
## AIFF-C:
## https://web.archive.org/web/20071219035740/http://www.cnpbagwell.com/aiff-c.txt
##
## Test files in any recent Python 3 distribution in Lib/test/audiodata/
def unpackAIFF(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}

        if filesize - offset < 12:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'Too small for AIFF or AIFF-C file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize = 0
        checkfile = open(filename, 'rb')
        ## skip over the header
        checkfile.seek(offset+4)
        checkbytes = checkfile.read(4)
        chunkdatasize = int.from_bytes(checkbytes, byteorder='big')

        ## check if the file has enough bytes to be a valid AIFF or AIFF-C
        if offset + chunkdatasize + 8 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'chunk size bigger than file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 8

        checkbytes = checkfile.read(4)

        if not (checkbytes == b'AIFF' or checkbytes == b'AIFC'):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong form type'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for chunk id'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                ## store the name of the chunk, as a few chunk names are mandatory
                chunknames.add(chunkid)
                unpackedsize += 4

                ## read the size of the chunk
                checkbytes = checkfile.read(4)
                if len(chunkid) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for chunk'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                chunksize = int.from_bytes(checkbytes, byteorder='big')
                ## chunk sizes should be even, so add a padding byte if necessary
                if chunksize % 2 != 0:
                        chunksize += 1
                ## check if the chunk isn't outside of the file
                if checkfile.tell() + chunksize > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'declared chunk size outside file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4
                checkfile.seek(chunksize, os.SEEK_CUR)
                unpackedsize += chunksize

        ## chunks "COMM" and "SSND" are mandatory
        if not b'COMM' in chunknames:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Mandatory chunk \'COMM\' not found.'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        if not b'SSND' in chunknames:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Mandatory chunk \'SSND\' not found.'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels += ['audio', 'aiff', aifftype]
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file. It is anonymous, so just give it a name
        outfilename = os.path.join(unpackdir, "unpacked-aiff")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((outfilename, ['audio', 'aiff', 'unpacked', aifftype]))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## terminfo files, format described in the Linux man page for terminfo files
## man 5 term
def unpackTerminfo(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## the header is 12 bytes long
        if filesize - offset < 12:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for header'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for names section or not enough data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        if namessectionsize < 2:
                ## man page says "this section is terminated with an ASCII NUL character"
                ## so it cannot be empty. The name of the terminal has to be at least one
                ## character.
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'names section size cannot be less than 2'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## regular compiled names section cannot exceed 4096
        if namessectionsize > 4096:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid names section size'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## the number of bytes in the boolean section, which follows the names section
        checkbytes = checkfile.read(2)
        booleansize = int.from_bytes(checkbytes, byteorder='little')
        if offset + 12 + namessectionsize + booleansize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for boolean bytes or not enough data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## the number section has to start on an even byte boundary
        ## so pad if necessary.
        booleanpadding = 0
        if (12 + namessectionsize + booleansize)%2 != 0:
                booleanpadding = 1

        ## the number of short integers in the numbers section, following the boolean section
        checkbytes = checkfile.read(2)
        numbershortints = int.from_bytes(checkbytes, byteorder='little')
        if offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2 > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for short ints or not enough data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## the number of shorts in the strings section, following the numbers section
        checkbytes = checkfile.read(2)
        stringoffsets = int.from_bytes(checkbytes, byteorder='little')
        if offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2 + stringoffsets*2> filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for string offsets or not enough data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        stringstableoffset = offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2 + stringoffsets*2

        ## the size of the string table following the strings section
        checkbytes = checkfile.read(2)
        stringstablesize = int.from_bytes(checkbytes, byteorder='little')
        if stringstableoffset + stringstablesize> filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for strings table or not enough data'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## names in the namessection size have to be printable.
        checkfile.seek(offset + 12)
        checkbytes = checkfile.read(namessectionsize)
        for n in checkbytes[:-1]:
                if not chr(n) in string.printable:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid character in names section'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## skip to the end of the namessection and check if there is a NUL
        if checkbytes[-1] != 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'names section not terminated with NUL'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## first skip to the start of the boolean section and check all the booleans
        checkfile.seek(offset + 12 + namessectionsize)
        for n in range(0,booleansize):
                checkbytes = checkfile.read(1)
                if checkbytes != b'\x00' and checkbytes != b'\x01':
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid value for boolean table entry'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        maxoffset = -1

        ## then check each of the offsets from the string offsets section in the strings table.
        ## This doesn't work well for some terminfo files, such as jfbterm, kon, kon2, screen.xterm-xfree86
        ## probably due to wide character support.
        checkfile.seek(offset + 12 + namessectionsize + booleansize + booleanpadding + numbershortints*2)
        for n in range(0,stringoffsets):
                checkbytes = checkfile.read(2)
                if checkbytes == b'\xff\xff':
                        continue
                stringoffset = int.from_bytes(checkbytes, byteorder='little')
                if stringstableoffset + stringoffset > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': unpackedsize, 'fatal': False, 'reason': 'invalid offset for string table entry'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                maxoffset = max(maxoffset, stringstableoffset + stringoffset)

        ## then skip to the end of the string table
        checkfile.seek(stringstableoffset + stringstablesize)
        unpackedsize = stringstableoffset + stringstablesize - offset

        if offset == 0 and unpackedsize == filesize:
                checkfile.close()
                labels.append('terminfo')
                labels.append('resource')
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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

                ## read the location of the last offset in the extended string table
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
                ## compare _nc_read_termtype() from ncurses/tinfo/read_entry.c from the ncurses 6.1
                ## release.
                ##
                ## Easy hack: use the last offset in the string table
                if validextension:
                        checkbytes = checkfile.read(extendedboolean + extendednumeric)
                        if len(checkbytes) != extendedboolean + extendednumeric:
                                validextension = False
                        ## there might be a NUL byte, but this doesn't hold for every
                        ## file seen in the wild so ignore for now.
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
                return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve.
        checkfile.seek(offset)
        outfilename = os.path.join(unpackdir, "unpacked-from-term")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((outfilename, ['terminfo', 'resource', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://rzip.samba.org/
## https://en.wikipedia.org/wiki/Rzip
def unpackRzip(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    if filesize - offset < 10:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'File too small (less than 10 bytes'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    if shutil.which('rzip') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'rzip program not found'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid major version number %d' % ord(checkbytes)}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'no valid bzip2 header found'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## uncompress the bzip2 data
        bzip2res = unpackBzip2(filename, bzip2pos, unpackdir, temporarydirectory, dryrun=True)
        if not bzip2res[0]:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'no valid bzip2 data'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        checkfile.seek(bzip2pos + bzip2res[1])
        unpackedsize = checkfile.tell() - offset

        ## check if there could be another block with bzip2 data
        ## the data between the bzip2 blocks is 13 bytes (rzip source code,
        ## file: stream.c, function: fill_buffer()
        if filesize - (bzip2res[1] + bzip2pos) < 13:
            break

        checkfile.seek(13, os.SEEK_CUR)
        checkbytes = checkfile.read(3)
        if checkbytes != b'BZh':
            break

        checkfile.seek(-3, os.SEEK_CUR)

    if not filename.endswith('.rz'):
        outfilename = os.path.join(unpackdir, "unpacked-from-rzip")
    else:
        outfilename = os.path.join(unpackdir, os.path.basename(filename[:-3]))

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        p = subprocess.Popen(['rzip', '-k', '-d', filename, '-o', outfilename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid RZIP file'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if os.stat(outfilename).st_size != uncompressedsize:
            os.unlink(outfilename)
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'unpacked RZIP data does not match declared uncompressed size'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedfilesandlabels.append((outfilename, []))
        labels.append('compressed')
        labels.append('rzip')

        return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

    else:
        temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
        os.fdopen(temporaryfile[0]).close()
        checkfile.close()
        p = subprocess.Popen(['rzip', '-d', temporaryfile[1], '-o', outfilename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            os.unlink(temporaryfile[1])
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid RZIP file'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if os.stat(outfilename).st_size != uncompressedsize:
            os.unlink(outfilename)
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'unpacked RZIP data does not match declared uncompressed size'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedfilesandlabels.append((outfilename, []))

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Derived from specifications at:
## https://en.wikipedia.org/wiki/Au_file_format
##
## Test files in any recent Python 3 distribution in Lib/test/audiodata/
def unpackAU(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    if filesize - offset < 24:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'Too small for AU file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    unpackedsize = 0
    checkfile = open(filename, 'rb')

    ## skip over the header
    checkfile.seek(offset+4)
    checkbytes = checkfile.read(4)
    dataoffset = int.from_bytes(checkbytes, byteorder='big')
    if dataoffset % 8 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'data offset not divisible by 8'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    if offset + dataoffset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'data offset cannot be outside of file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 8

    ## read the length
    checkbytes = checkfile.read(4)
    unpackedsize += 4

    ## only support files that have the data size embedded in the header
    if checkbytes != b'\xff\xff\xff\xff':
        datasize = int.from_bytes(checkbytes, byteorder='big')

        ## According to Wikipedia and the OpenGroup just a limited number
        ## of encodings are in use
        checkbytes = checkfile.read(4)
        encoding = int.from_bytes(checkbytes, byteorder='big')
        if not encoding in set([1,2,3,4,5,6,7,8,9,10,11,12,13,18,19,20,21,23,24,25,26,27]):
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong encoding value'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'data offset cannot start inside header'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        checkfile.seek(offset + dataoffset)
        unpackedsize = dataoffset

        ## there has to be enough data for the audio
        if offset + dataoffset + datasize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'AU data cannot be outside of file'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## finally the data, just skip over it
        unpackedsize += datasize
        if offset == 0 and unpackedsize == filesize:
            checkfile.close()
            labels += ['audio', 'au']
            return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## else carve the file. It is anonymous, so give it a name
        outfilename = os.path.join(unpackdir, "unpacked-au")
        outfile = open(outfilename, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        unpackedfilesandlabels.append((outfilename, ['audio', 'au', 'unpacked']))
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    ## default case: nothing unpacked
    checkfile.close()
    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'Cannot determine size for AU file'}
    return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## JFFS2 https://en.wikipedia.org/wiki/JFFS2
## JFFS2 is a file system that was used on earlier embedded Linux system, although
## it is no longer the first choice for modern systems, where for example UBI/UBIFS
## are chosen.
def unpackJFFS2(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        if filesize - offset < 12:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'File too small (less than 12 bytes'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

        validinodes = set([DIRENT, INODE, CLEANMARKER, PADDING, SUMMARY, XATTR, XREF])

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
                ## specific implementation for computing checksum grabbed from MIT licensed script found
                ## at:
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
                                ## the inode number is already known, meaning that this should be a hard link
                                os.link(os.path.join(unpackdir, inodetofilename[inodenumber]), os.path.join(unpackdir, inodename))

                                ## TODO: determine whether or not to add the hard link to the result set
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
                                ## it is 0, or it is the previous offset, plus the previous
                                ## uncompressed length.
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
                                        ## The data is LZMA compressed, so create a LZMA decompressor
                                        ## with custom filter, as the data is stored without LZMA headers.
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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'no data unpacked'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## close all the open files
        for i in inodetoopenfiles:
                inodetoopenfiles[i].flush()
                inodetoopenfiles[i].close()
                unpackedfilesandlabels.append((inodetoopenfiles[i].name,[]))

        ## check if a valid root node was found.
        if not 1 in parentinodesseen:
                for i in inodetoopenfiles:
                        os.unlink(inodetoopenfiles[i])
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'no valid root file node'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        if offset == 0 and filesize == unpackedsize:
                labels.append('jffs2')
                labels.append('file system')
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## old binary format has a 26 byte header
        ## portable ASCII format has a 76 byte header
        ## new formats have a 110 byte header
        if filesize - offset < 26:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
                        ## "For all other entry types, it should be set to zero by writers and ignored by readers."
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for header'}
                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                        ## "For all other entry types, it should be set to zero by writers and ignored by readers."
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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes for header'}
                                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                        ## "For all other entry types, it should be set to zero by writers and ignored by readers."
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
                        ## "For all other entry types, it should be set to zero by writers and ignored by readers."
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
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid CPIO file'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                ## no trailer was found, but data was unpacked, so tag the archive
                ## as corrupt and partially unpacked.
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

        if offset == 0 and filesize == unpackedsize:
                labels.append('cpio')
                labels.append('archive')
        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://en.wikipedia.org/wiki/7z
## Inside the 7z distribution there is a file called
##
## DOC/7zFormat.txt
##
## that describes the file format.
##
## This unpacker can recognize 7z formats, but only if the 7z file consists
## of a single frame.
def unpack7z(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## a 7z signature header is at least 32 bytes
        if filesize - offset < 32:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## open the file and skip the magic
        checkfile = open(filename, 'rb')
        checkfile.seek(offset + 6)
        unpackedsize += 6

        ## read the major version. This has been 0 for a long time.
        majorversion = ord(checkfile.read(1))
        if majorversion > 0:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid major version'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data for header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        crccomputed = binascii.crc32(checkbytes)

        if nextheadercrc != crccomputed:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid header CRC'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## first try to find the offset of the next header and read
        ## some metadata for it.
        nextheaderoffset = int.from_bytes(checkbytes[0:8], byteorder='little')
        nextheadersize = int.from_bytes(checkbytes[8:16], byteorder='little')
        nextheadercrc = int.from_bytes(checkbytes[16:20], byteorder='little')

        if checkfile.tell() + nextheaderoffset + nextheadersize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'next header offset outside file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## Then skip to the next offset
        checkfile.seek(checkfile.tell() + nextheaderoffset)

        ## extra sanity check: compute the header CRC for the
        ## next header...
        checkbytes = checkfile.read(nextheadersize)
        computedcrc = binascii.crc32(checkbytes)

        ## ...and compare it to the stored CRC
        if computedcrc != nextheadercrc:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid next header CRC'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize = checkfile.tell() - offset

        if shutil.which('7z') == None:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': '7z program not found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid 7z file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## Windows Compiled HTML help
## https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help
## http://web.archive.org/web/20021209123621/www.speakeasy.org/~russotto/chm/chmformat.html
def unpackCHM(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## header has at least 56 bytes
        if filesize < 56:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## open the file and skip the magic and the version number
        checkfile = open(filename, 'rb')
        checkfile.seek(offset+8)
        unpackedsize += 8

        ## total header length
        checkbytes = checkfile.read(4)
        chmheaderlength = int.from_bytes(checkbytes, byteorder='little')
        if offset + chmheaderlength > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'declared header outside of file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for section offset'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                sectionoffset = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 8

                ## and a section size
                checkbytes = checkfile.read(8)
                if len(checkbytes) != 8:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for section size'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                sectionsize = int.from_bytes(checkbytes, byteorder='little')

                ## sanity check: sections cannot be outside of the file
                if offset + sectionoffset + sectionsize > filesize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'sections outside of file'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 8

        ## then the offset of content section 0, that isn't there in version 2, but
        ## version 2 is not supported anyway.
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for content section offset'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        contentsection0offset = int.from_bytes(checkbytes, byteorder='little')
        if offset + contentsection0offset > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'content section 0 outside of file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 8

        ## then skip 8 bytes
        checkfile.seek(8, os.SEEK_CUR)
        unpackedsize += 8

        ## read the file size
        checkbytes = checkfile.read(8)
        if len(checkbytes) != 8:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for file size'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        chmsize = int.from_bytes(checkbytes, byteorder='little')
        if offset + chmsize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'declared CHM size larger than file size'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 8

        if shutil.which('7z') == None:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': '7z program not found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not a valid CHM file'}

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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid CHM file'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## a WIM signature header is at least 208 bytes
    if filesize - offset < 208:
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough data'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## open the file and skip the magic
    checkfile = open(filename, 'rb')
    checkfile.seek(offset + 8)
    unpackedsize += 8

    ## now read the size of the header
    checkbytes = checkfile.read(4)
    headersize = int.from_bytes(checkbytes, byteorder='little')
    if headersize < 208:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid header size'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    if offset + headersize > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'declared header size bigger than file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'cannot unpack multipart WIM'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 2

    ## the total numbers of WIM parts
    checkbytes = checkfile.read(2)
    totalwimparts = int.from_bytes(checkbytes, byteorder='little')
    if totalwimparts != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'cannot unpack multipart WIM'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 2

    ## the image count
    checkbytes = checkfile.read(4)
    wimimagecount = int.from_bytes(checkbytes, byteorder='little')
    if wimimagecount != 1:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'cannot unpack multipart WIM'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## the resources offset table are stored in a reshdr_disk_short structure
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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'resource outside of file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'resource outside of file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 8

    ## then the original size of the XML
    checkbytes = checkfile.read(8)
    xmlorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## any boot information is also stored in a reshdr_disk_short structure
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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'resource outside of file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 8

    ## then the original size of the boot data
    checkbytes = checkfile.read(8)
    bootorigsize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 8

    ## the boot index
    checkbytes = checkfile.read(4)
    bootindex = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    ## the integrity table is also stored in a reshdr_disk_short structure
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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'resource outside of file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid XML stored in WIM'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    if shutil.which('7z') == None:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': '7z program not found'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid WIM file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://www.fileformat.info/format/sunraster/egff.htm
## This is not a perfect catch and Only some raster files
## might be labeled as such.
def unpackSunRaster(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    ## header has 8 fields, each 4 bytes
    if filesize - offset < 32:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'raster files with length 0 defined not supported'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## check type. Typical values are 0, 1, 2, 3, 4, 5 and 0xffff
    checkbytes = checkfile.read(4)
    ras_type = int.from_bytes(checkbytes, byteorder='big')
    if not ras_type in [0,1,2,3,4,5,0xffff]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unknown raster type field'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    if ras_type != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'only standard type is supported'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## check the color map type. Typical values are 0, 1, 2
    checkbytes = checkfile.read(4)
    ras_maptype = int.from_bytes(checkbytes, byteorder='big')
    if not ras_maptype in [0,1,2]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'unknown color map type field'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## length of colormap
    checkbytes = checkfile.read(4)
    ras_maplength = int.from_bytes(checkbytes, byteorder='big')

    ## check if the header + length of data + length of color map are inside the file
    if 32 + offset + ras_maplength + ras_length > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for raster file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    ## skip over the rest
    unpackedsize += 4 + ras_maplength + ras_length

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('sun raster')
        labels.append('raster')
        labels.append('binary')
        labels.append('graphics')
        return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

    ## Carve the image.
    ## first reset the file pointer
    checkfile.seek(offset)
    outfilename = os.path.join(unpackdir, "unpacked.rast")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['binary', 'sun raster', 'raster', 'graphics', 'unpacked']))
    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://en.wikipedia.org/wiki/Intel_HEX
## For now it is assumed that only files that are completely text
## files can be IHex files.
def unpackIHex(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        allowbroken = False

        ## open the file in text mode and process each line
        checkfile = open(filename, 'r')
        checkfile.seek(offset)

        outfilename = os.path.join(unpackdir, "unpacked-from-ihex")
        if filename.lower().endswith('.hex'):
                outfilename = os.path.join(unpackdir, os.path.basename(filename[:-4]))
        elif filename.lower().endswith('.ihex'):
                outfilename = os.path.join(unpackdir, os.path.basename(filename[:-5]))

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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'line does not start with :'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        ## minimum length for a line is:
                        ## 1 + 2 + 4 + 2 + 2 = 11
                        ## Each byte uses two characters. The start code uses 1 character.
                        ## That means that each line has an uneven length.
                        if len(line.strip()) < 11 or len(line.strip())%2 != 1:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfilename)
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes in line'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        bytescount = int.from_bytes(bytes.fromhex(line[1:3]), byteorder='big')
                        if 3 + bytescount + 2 > len(line.strip()):
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfilename)
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes in line'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        ## the base address is from 3:7 and can be skipped
                        ## the record type is next from 7:9
                        recordtype = int.from_bytes(bytes.fromhex(line[7:9]), byteorder='big')
                        if recordtype > 5:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfilename)
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid record type'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'cannot convert to hex'}
                                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                                outfile.write(ihexdata)
                        seenrecordtypes.add(recordtype)

                        unpackedsize += len(line.strip()) + len(checkfile.newlines)

                        if endofihex:
                                break
        except UnicodeDecodeError:
                checkfile.close()
                outfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not a text file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        checkfile.close()
        outfile.close()

        if 4 in seenrecordtypes or 5 in seenrecordtypes:
                if 3 in seenrecordtypes:
                        os.unlink(outfilename)
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'incompatible record types combined'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## each valid IHex file has to have a terminator
        if not endofihex and not allowbroken:
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no end of data found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        unpackedfilesandlabels.append((outfilename, []))
        if offset == 0 and filesize == unpackedsize:
                labels.append('text')
                labels.append('ihex')

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://en.wikipedia.org/wiki/SREC_(file_format)
## For now it is assumed that only files that are completely text
## files can be SREC files.
def unpackSREC(filename, offset, unpackdir, temporarydirectory):
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        allowbroken = False

        ## open the file in text mode and process each line
        checkfile = open(filename, 'r')
        checkfile.seek(offset)

        outfilename = os.path.join(unpackdir, "unpacked-from-srec")
        if filename.lower().endswith('.srec'):
                outfilename = os.path.join(unpackdir, os.path.basename(filename[:-5]))

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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'line does not start with S'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        ## minimum length for a line is:
                        ## 2 + 2 + 4 + 2 = 10
                        ## Each byte uses two characters. The record type uses two characters.
                        ## That means that each line has an even length.
                        if len(line.strip()) < 10 or len(line.strip())%2 != 0:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfilename)
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes in line'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

                        ## then the type. S0 is optional and has no data, S4 is
                        ## reserved and S5 and S6 are not that interesting.
                        if line[:2] == 'S1' or line[:2] == 'S2' or line[:2] == 'S3':
                                isdata = True
                        elif line[:2] == 'S7' or line[:2] == 'S8' or line[:2] == 'S9':
                                seenterminator = True
                        recordtype = line[:2]
                        seenrecords.add(recordtype)

                        ## then the byte count
                        bytescount = int.from_bytes(bytes.fromhex(line[2:4]), byteorder='big')
                        if bytescount < 3:
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfilename)
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'bytecount too small'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                        if 4 + bytescount * 2 != len(line.strip()):
                                checkfile.close()
                                outfile.close()
                                os.unlink(outfilename)
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough bytes in line'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'cannot convert to hex'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not a text file'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        checkfile.close()
        outfile.close()

        ## each valid SREC file has to have a terminator
        if not seenterminator and not allowbroken:
                os.unlink(outfilename)
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'no terminator record found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## sanity checks for the records: only certain combinations are allowed
        if 'S1' in seenrecords:
                if 'S2' in seenrecords or 'S3' in seenrecords:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'incompatible data records mixed'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if 'S7' in seenrecords or 'S8' in seenrecords:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'incompatible terminator records mixed'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        elif 'S2' in seenrecords:
                if 'S3' in seenrecords:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'incompatible data records mixed'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                if 'S7' in seenrecords or 'S9' in seenrecords:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'incompatible terminator records mixed'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        elif 'S3' in seenrecords:
                if 'S8' in seenrecords or 'S9' in seenrecords:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'incompatible terminator records mixed'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        unpackedfilesandlabels.append((outfilename, []))
        if offset == 0 and filesize == unpackedsize:
                labels.append('text')
                labels.append('srec')

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}
        unpackedsize = 0

        ## superblock starts at offset 1024 and is 1024 bytes (section 3.1)
        if filesize - offset < 2048:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for superblock'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        if shutil.which('e2ls') == None:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'e2ls program not found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        if shutil.which('e2cp') == None:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'e2cp program not found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## open the file and skip directly to the superblock
        checkfile = open(filename, 'rb')
        checkfile.seek(offset+1024)
        unpackedsize += 1024

        ## Process the superblock and run many sanity checks.
        ## Extract the total number of inodes in the file system (section 3.1.1)
        checkbytes = checkfile.read(4)
        totalinodecount = int.from_bytes(checkbytes, byteorder='little')
        if totalinodecount == 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'inodes cannot be 0'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## the total number of blocks in the file system (section 3.1.2)
        checkbytes = checkfile.read(4)
        totalblockcount = int.from_bytes(checkbytes, byteorder='little')
        if totalblockcount == 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'block count cannot be 0'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## reserved block count for the superuser (section 3.1.3)
        checkbytes = checkfile.read(4)
        reservedblockcount = int.from_bytes(checkbytes, byteorder='little')
        if reservedblockcount > totalblockcount:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'reserved blocks cannot exceed total blocks'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## free blocks in the system (section 3.1.4)
        checkbytes = checkfile.read(4)
        freeblockcount = int.from_bytes(checkbytes, byteorder='little')
        if freeblockcount > totalblockcount:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'free blocks cannot exceed total blocks'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## free inodes in the system (section 3.1.5)
        checkbytes = checkfile.read(4)
        freeinodes = int.from_bytes(checkbytes, byteorder='little')
        if freeinodes > totalinodecount:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'free inodes cannot exceed total inodes'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## location of the first data block. Has to be 0 or 1. (section 3.1.6)
        checkbytes = checkfile.read(4)
        firstdatablock = int.from_bytes(checkbytes, byteorder='little')
        if firstdatablock != 0 and firstdatablock != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for first data block'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## the block size (section 3.1.7)
        checkbytes = checkfile.read(4)
        blocksize = 1024 << int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += 4

        ## check if the declared size is bigger than the file's size
        if offset + (totalblockcount * blocksize) > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'declared file system size larger than file size'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## skip 4 bytes
        checkfile.seek(4, os.SEEK_CUR)
        unpackedsize += 4

        ## determine the blocks per group (section 3.1.9)
        checkbytes = checkfile.read(4)
        blocks_per_group = int.from_bytes(checkbytes, byteorder='little')
        if blocks_per_group == 0:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for blocks per group'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid ext2/3/4 revision'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## skip 8 bytes
        checkfile.seek(8, os.SEEK_CUR)
        unpackedsize += 8

        ## read the inode size, cannot be larger than block size (section 3.1.27)
        checkbytes = checkfile.read(2)
        inodesize = int.from_bytes(checkbytes, byteorder='little')
        if inodesize > blocksize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'inode size cannot be larger than block size'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
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

        ## Now check for each block group if there is a copy of the superblock
        ## except if the sparse super block features is set (section 2.5)
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
                                continue

                ## jump to the location of the magic header (section 3.1.16)
                ## and check its value. In a valid super block this value should
                ## always be the same.
                checkfile.seek(blockoffset + 0x38)
                checkbytes = checkfile.read(2)
                if not checkbytes == b'\x53\xef':
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid super block copy'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize = totalblockcount * blocksize

        ## e2tools can work with trailing data, but if there is any data preceding
        ## the file system then some carving has to be done first.
        havetmpfile = False
        if not offset == 0:
                temporaryfile = tempfile.mkstemp(dir=temporarydirectory)
                os.sendfile(temporaryfile[0], checkfile.fileno(), offset, unpackedsize)
                os.fdopen(temporaryfile[0]).close()
                havetmpfile = True
        checkfile.close()

        ## Now read the contents of the file system with e2ls and copy with e2cp
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
                p = subprocess.Popen(['e2ls', '-lai', filename + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (outputmsg, errormsg) = p.communicate()
                if p.returncode != 0:
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'e2ls error'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                               unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'could not decode file name'}
                               return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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
                                        p = subprocess.Popen(['e2cp', filename + ":" + fullext2name, "-d", os.path.join(unpackdir, ext2dir)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                        (outputmsg, errormsg) = p.communicate()
                                        if p.returncode != 0:
                                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'e2cp error'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'no data unpacked'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        if offset == 0 and filesize == unpackedsize:
                labels.append('ext2')
                labels.append('file system')

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
        filesize = os.stat(filename).st_size
        unpackedfilesandlabels = []
        labels = []
        unpackingerror = {}

        ## the RPM lead is 96 bytes (section 22.2.1)
        if filesize - offset < 96:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'File too small (less than 96 bytes'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        unpackedsize = 0

        ## open the file and skip the magic
        checkfile = open(filename, 'rb')
        checkfile.seek(offset+4)
        unpackedsize += 4

        ## then process the RPM lead. Many of these values are duplicated in the
        ## header later in the file.

        ## read the major version. The standard version is 3. There have been
        ## files with major 4.
        checkbytes = checkfile.read(1)
        majorversion = ord(checkbytes)
        if majorversion > 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not a valid RPM major version'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not a valid RPM type'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## read the architecture
        checkbytes = checkfile.read(2)
        unpackedsize += 2

        ## the name of the file, should be NUL terminated
        checkbytes = checkfile.read(66)
        if not b'\x00' in checkbytes:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'name not NUL terminated'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 66

        ## osnum: "shall be 1"
        checkbytes = checkfile.read(2)
        osnum = int.from_bytes(checkbytes, byteorder='big')
        if osnum != 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'osnum not 1'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## signature type: "shall be 5"
        checkbytes = checkfile.read(2)
        signaturetype = int.from_bytes(checkbytes, byteorder='big')
        if signaturetype != 5:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'signature type not 5'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 2

        ## skip over the 'reserved space'
        checkfile.seek(16, os.SEEK_CUR)
        unpackedsize += 16

        ## signature, in header format (section 22.2.2 and 22.2.3)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for signature'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if checkbytes != b'\x8e\xad\xe8\x01':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong magic for signature'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## reserved space
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for signature reserved space'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if checkbytes != b'\x00\x00\x00\x00':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'incorrect values for signature rserved space'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## number of index records, should be at least 1
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for signature index record count'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        signatureindexrecordcount = int.from_bytes(checkbytes, byteorder='big')
        if signatureindexrecordcount < 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for signature index record count'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## the size of the storage area for the data pointed to by the index records
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record size'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        signaturehsize = int.from_bytes(checkbytes, byteorder='big')
        unpackedsize += 4

        ## process all the index records (section 22.2.2.2)
        for i in range(0,signatureindexrecordcount):
                ## first the tag
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record tag'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## then the type
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record type'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## then the offset
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record offset'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                indexoffset = int.from_bytes(checkbytes, byteorder='big')
                if indexoffset > signaturehsize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid index record offset'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## the size of the record
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index count'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                indexcount = int.from_bytes(checkbytes, byteorder='big')
                unpackedsize += 4

        ## then the signature size
        if checkfile.tell() + signaturehsize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for signature storage area'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        checkfile.seek(signaturehsize, os.SEEK_CUR)
        unpackedsize += signaturehsize

        ## then pad on an 8 byte boundary
        if unpackedsize%8 != 0:
                checkfile.seek(8 - unpackedsize%8, os.SEEK_CUR)
                unpackedsize += 8 - unpackedsize%8

        ## Next is the Header, which is identical to the Signature (section 22.2.2 and 22.2.3)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if checkbytes != b'\x8e\xad\xe8\x01':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong magic for header'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## reserved space
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for header reserved space'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if checkbytes != b'\x00\x00\x00\x00':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'incorrect values for header rserved space'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## number of index records, should be at least 1
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for header index record count'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        headerindexrecordcount = int.from_bytes(checkbytes, byteorder='big')
        if headerindexrecordcount < 1:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong value for header index record count'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4

        ## the size of the storage area for the data pointed to by the index records
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record size'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record tag'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                headertag = int.from_bytes(checkbytes, byteorder='big')
                unpackedsize += 4

                ## then the type
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record type'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                headertype = int.from_bytes(checkbytes, byteorder='big')
                unpackedsize += 4

                ## then the offset
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index record offset'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                indexoffset = int.from_bytes(checkbytes, byteorder='big')
                if indexoffset > headerhsize:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'invalid index record offset'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                unpackedsize += 4

                ## the size of the record
                checkbytes = checkfile.read(4)
                if len(checkbytes) != 4:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for index count'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                indexcount = int.from_bytes(checkbytes, byteorder='big')
                unpackedsize += 4

                if not headertag in headertagtooffsets:
                        headertagtooffsets[headertag] = (indexoffset, indexcount, headertype)

        ## then the header size
        if checkfile.tell() + headerhsize > filesize:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for header storage area'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

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

                ## depending on the type a different size has to be read (section 22.2.2.2.1)
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

        ## then unpack the file. This depends on the compressor and the payload format.
        ## The default compressor is either gzip or XZ (on Fedora). Other supported
        ## compressors are bzip2, LZMA and zstd (recent addition).
        ## 1125 is the tag for the compressor.
        if not 1125 in tagstoresults:
                ## gzip by default
                unpackresult = unpackGzip(filename, checkfile.tell(), unpackdir, temporarydirectory)
        else:
                if len(tagstoresults[1125]) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'duplicate compressor defined'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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

        if not unpackresult[0]:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'could not decompress payload'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        (rpmunpacksize, rpmunpackfiles) = unpackresult[1:3]
        if len(rpmunpackfiles) != 1:
                ## this should never happen
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'could not decompress payload'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        payload = None
        payloadfile = rpmunpackfiles[0][0]

        ## 1124 is the payload. Only 'cpio' can be unpacked at the moment.
        if 1124 in tagstoresults:
                if len(tagstoresults[1124]) != 1:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'duplicate payload defined'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                payload = tagstoresults[1124][0]
                if payload == b'cpio':
                        ## first move the payload file to a different location
                        ## to avoid name clashes with the
                        payloaddir = tempfile.mkdtemp(dir=temporarydirectory)
                        shutil.move(payloadfile, payloaddir)
                        unpackresult = unpackCpio(os.path.join(payloaddir, os.path.basename(payloadfile)), 0, unpackdir, temporarydirectory)
                        ## cleanup
                        shutil.rmtree(payloaddir)
                        if not unpackresult[0]:
                                checkfile.close()
                                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'could not unpack CPIO payload'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                        for i in unpackresult[2]:
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

        return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## zstd
## https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
def unpackZstd(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    if shutil.which('zstd') == None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'zstd program not found'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    checkfile = open(filename, 'rb')
    ## skip the magic
    checkfile.seek(offset+4)
    unpackedsize += 4

    ## then read the frame header descriptor as it might indicate whether or
    ## not there is a size field
    checkbytes = checkfile.read(1)
    if len(checkbytes) != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for zstd frame header'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    if ord(checkbytes) & 32 == 0:
        single_segment = False
    else:
        single_segment = True

    ## process the frame header descriptor to see how big the frame header is
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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'reserved bit set'}
        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for window descriptor'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 1

    ## then read the dictionary
    if did_field_size != 0:
        checkbytes = checkfile.read(did_field_size)
        if len(checkbytes) != did_field_size:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for dictionary'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += did_field_size

    if fcs_field_size != 0:
        checkbytes = checkfile.read(fcs_field_size)
        if len(checkbytes) != fcs_field_size:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for frame content size'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        uncompressed_size = int.from_bytes(checkbytes, byteorder='little')
        unpackedsize += fcs_field_size

    ## then the blocks: each block starts with 3 bytes
    while True:
        lastblock = False
        checkbytes = checkfile.read(3)
        if len(checkbytes) != 3:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for frame'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        ## first check if it is the last block
        if checkbytes[0] & 1 == 1:
            lastblock = True
        blocksize = int.from_bytes(checkbytes, byteorder='little') >> 3
        if checkfile.tell() + blocksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for frame'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        checkfile.seek(blocksize, os.SEEK_CUR)
        if lastblock:
            break

    if content_checksum_set:
        ## lower 32 bytes of xxHash checksum of the original decompressed data
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for checksum'}
            return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

    unpackedsize = checkfile.tell() - offset

    ## zstd does not record the name of the file that was
    ## compressed, so guess, or just set a name.
    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        if filename.endswith(".zst"):
            outfilename = os.path.join(unpackdir, os.path.basename(filename)[:-4])
        else:
            outfilename = os.path.join(unpackdir, "unpacked-by-zstd")
        p = subprocess.Popen(['zstd', '-d', '-o', outfilename, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        if p.returncode != 0:
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid zstd'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if fcs_field_size != 0:
            if uncompressed_size != os.stat(outfilename).st_size:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid checksum'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
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
            unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid zstd'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        if fcs_field_size != 0:
            if uncompressed_size != os.stat(outfilename).st_size:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid checksum'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

    unpackedfilesandlabels.append((outfilename, []))
    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

## https://en.wikipedia.org/wiki/Apple_Icon_Image_format
def unpackAppleIcon(filename, offset, unpackdir, temporarydirectory):
    filesize = os.stat(filename).st_size
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
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for icon length'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    appleiconlength = int.from_bytes(checkbytes, byteorder='big')

    ## data cannot be outside of file
    if appleiconlength + offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'icon cannot be outside of file'}
        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
    unpackedsize += 4

    ## then the actual icon data
    while unpackedsize < appleiconlength:
        ## first the icon type
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough icon data for icon type'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        icontype = checkbytes
        unpackedsize += 4

        ## then the icon data length (including type and length)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough icon data'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        iconlength = int.from_bytes(checkbytes, byteorder='big')
        ## icon length cannot be outside of the file. The length field includes
        ## the type and length, and unpackedsize already has 4 bytes of the
        ## type added, so subtract 4 in the check.
        if offset + unpackedsize - 4 + iconlength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'icon data outside of file'}
            return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
        unpackedsize += 4
        checkfile.seek(iconlength-8, os.SEEK_CUR)
        unpackedsize += iconlength-8

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('apple icon')
        labels.append('graphics')
        labels.append('resource')
        return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

    ## Carve the image.
    ## first reset the file pointer
    checkfile.seek(offset)
    outfilename = os.path.join(unpackdir, "unpacked.icns")
    outfile = open(outfilename, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfilename, ['apple icon', 'graphics', 'resource', 'unpacked']))
    return (True, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
