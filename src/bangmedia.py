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

# Built in carvers/verifiers/unpackers for various media files (graphics,
# video, audio, PDF).
#
# For these unpackers it has been attempted to reduce disk I/O as much
# as possible using the os.sendfile() method, as well as techniques
# described in this blog post:
#
# https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import os
import binascii
import math
import lzma
import zlib
import re


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


# An unpacker for the SWF format, able to carve/label zlib &
# LZMA compressed SWF files as well as uncompressed files.
# Uses the description of the SWF file format as described here:
#
# https://wwwimages2.adobe.com/content/dam/acom/en/devnet/pdf/swf-file-format-spec.pdf
#
# The format is described in chapter 2 and Appendix A.
def unpack_swf(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a SWF file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    labels = []
    unpackedfilesandlabels = []
    unpackingerror = {}
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    unpackedsize = 0

    # First check if the file size is 8 bytes or more.
    # If not, then it is not a valid SWF file
    if filesize - offset < 8:
        unpackingerror = {'offset': offset, 'reason': 'fewer than 8 bytes',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    # Then open the file and read the first three bytes to see
    # if they respond to any of these SWF types:
    #
    # * uncompressed
    # * compressed with zlib
    # * compressed with LZMA
    checkfile = open(filename_full, 'rb')
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

    # Then the version number
    # As of August 2018 it is at 40:
    # https://www.adobe.com/devnet/articles/flashplayer-air-feature-list.html
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

    # Then read four bytes and check the length (stored in
    # little endian format).
    # This length has different meanings depending on whether or not
    # compression has been used.
    checkbytes = checkfile.read(4)
    storedfilelength = int.from_bytes(checkbytes, byteorder='little')
    if storedfilelength == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'invalid declared file length',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    # first process uncompresed files
    if swftype == 'uncompressed':
        # the stored file length is the length of the entire
        # file, so it cannot be bigger than the size of the
        # actual fle.
        if storedfilelength > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset, 'reason': 'wrong length',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

        # read one byte to find how many bits are
        # needed for RECT (SWF specification, chapter 1)
        # highest bits are used for this
        checkbytes = checkfile.read(1)
        nbits = ord(checkbytes) >> 3

        # go back one byte
        checkfile.seek(-1, os.SEEK_CUR)

        # and read (5 + 4*nbits) bits, has to be byte aligned
        bitstoread = 5 + 4*nbits
        checkbytes = checkfile.read(math.ceil(bitstoread/8))

        # now process all of the bits
        bitcounter = 5

        # then the frame rate
        checkbytes = checkfile.read(2)
        framerate = int.from_bytes(checkbytes, byteorder='little')

        # and the frame size
        checkbytes = checkfile.read(2)
        framesize = int.from_bytes(checkbytes, byteorder='little')

        # then the tags
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

            # a few sanity checks for known tags
            if tagtype == 1:
                # a show frame tag has no body
                if taglength != 0:
                    checkfile.close()
                    unpackingerror = {'offset': offset,
                                      'reason': 'wrong length for ShowFrame tag',
                                      'fatal': False}
                    return {'status': False, 'error': unpackingerror}

            # then skip tag length bytes
            checkfile.seek(taglength, os.SEEK_CUR)
            if tagtype == 0:
                # end tag
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

        # Carve the file. It is anonymous, so just give it a name
        outfile_rel = os.path.join(unpackdir, "unpacked.swf")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        outlabels = ['swf', 'video', 'unpacked']
        unpackedfilesandlabels.append((outfile_rel, outlabels))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # the data is compressed, so keep reading the compressed data until it
    # can no longer be uncompressed

    # 8 bytes have already been read
    unpackedsize = 8

    # read 1 MB chunks
    chunksize = 1024*1024

    if swftype == 'zlib':
        #payload = b''
        decompressor = zlib.decompressobj()
        checkbytes = bytearray(chunksize)
        decompressedlength = 0
        while True:
            bytesread = checkfile.readinto(checkbytes)
            try:
                # uncompress the data and count the length, but
                # don't store the data.
                unpackeddata = decompressor.decompress(checkbytes)
                decompressedlength += len(unpackeddata)
                #payload += unpackeddata
                unpackedsize += len(checkbytes) - len(decompressor.unused_data)
                if len(decompressor.unused_data) != 0:
                    break
            except:
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

        # Carve the file. It is anonymous, so just give it a name
        outfile_rel = os.path.join(unpackdir, "unpacked.swf")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
        outfile.close()
        checkfile.close()
        outlabels = ['swf', 'zlib compressed swf', 'video', 'unpacked']
        unpackedfilesandlabels.append((outfile_rel, outlabels))
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # As standard LZMA decompression from Python does not
    # like this format and neither does lzmacat, so some tricks are needed
    # to be able to decompress this data.
    #
    # Also see:
    #
    # * https://bugzilla.mozilla.org/show_bug.cgi?format=default&id=754932
    # * http://dev.offerhq.co/ui/assets/js/plupload/src/moxie/build/swf2lzma/swf2lzma.py

    checkbytes = checkfile.read(4)
    compressedlength = int.from_bytes(checkbytes, byteorder='little')
    if offset + 12 + compressedlength + 5 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset, 'reason': 'wrong length',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize = 12
    checkfile.seek(offset+12)

    # now read 1 byte for the LZMA properties
    checkbytes = checkfile.read(1)
    unpackedsize += 1

    # compute the LZMA properties, according to
    # http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
    # section 1.1
    props = ord(checkbytes)
    lzma_pb = props // (9 * 5)
    props -= lzma_pb * 9 * 5
    lzma_lp = props // 9
    lzma_lc = props - lzma_lp * 9

    # and 4 for the dictionary size
    checkbytes = checkfile.read(4)
    dictionarysize = int.from_bytes(checkbytes, byteorder='little')
    unpackedsize += 4

    # Create a LZMA decompressor with custom filter, as the data
    # is stored without LZMA headers.
    swf_filters = [{'id': lzma.FILTER_LZMA1,
                    'dict_size': dictionarysize,
                    'lc': lzma_lc,
                    'lp': lzma_lp,
                    'pb': lzma_pb}]

    try:
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=swf_filters)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset,
                          'reason': 'unsupported LZMA properties',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    # read 1 MB chunks
    #payload = b''
    checkbytes = bytearray(chunksize)
    decompressedlength = 0
    while True:
        checkfile.readinto(checkbytes)
        try:
            # uncompress the data and count the length, but
            # don't store the data.
            unpackeddata = decompressor.decompress(checkbytes)
            decompressedlength += len(unpackeddata)
            #payload += unpackeddata
            unpackedsize += len(checkbytes) - len(decompressor.unused_data)
            if len(decompressor.unused_data) != 0:
                break
        except:
            # TODO: more specific exceptions
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

    # Carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.swf")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    outlabels = ['swf', 'lzma compressed swf', 'video', 'unpacked']
    unpackedfilesandlabels.append((outfile_rel, outlabels))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_swf.signatures = {'swf': b'FWS', 'swf_zlib': b'CWS', 'swf_lzma': b'ZWS'}
unpack_swf.pretty = 'swf'
unpack_swf.minimum_size = 8


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
