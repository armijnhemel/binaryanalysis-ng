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
import string
import math
import lzma
import zlib
import re
import datetime

# some external packages that are needed
import defusedxml.minidom
import PIL.Image

encodingstotranslate = ['utf-8', 'ascii', 'latin-1', 'euc_jp', 'euc_jis_2004',
                        'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                        'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                        'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                        'shift_jis_2004', 'shift_jisx0213']


# A verifier for the WebP file format.
# Uses the description of the WebP file format as described here:
#
# https://developers.google.com/speed/webp/docs/riff_container
#
# A blog post describing how this method was implemented can be
# found here:
#
# http://binary-analysis.blogspot.com/2018/06/walkthrough-webp-file-format.html
def unpack_webp(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a WebP file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []

    # a list of valid WebP chunk FourCC
    # also contains the deprecated FRGM
    validchunkfourcc = set([b'ALPH', b'ANIM', b'ANMF', b'EXIF', b'FRGM',
                            b'ICCP', b'VP8 ', b'VP8L', b'VP8X', b'XMP '])
    unpackres = unpack_riff(fileresult, scanenvironment, offset, unpackdir, validchunkfourcc, 'WebP', b'WEBP')
    if unpackres['status']:
        labels = unpackres['labels']
        if offset == 0 and unpackres['length'] == filesize:
            labels += ['webp', 'graphics']
        for result in unpackres['filesandlabels']:
            unpackedfilesandlabels.append((result, ['webp', 'graphics', 'unpacked']))
        return {'status': True, 'length': unpackres['length'],
                'filesandlabels': unpackedfilesandlabels, 'labels': labels}
    return {'status': False, 'error': unpackres['error']}

unpack_webp.signatures = {'webp': b'WEBP'}
unpack_webp.offset = 8
unpack_webp.minimum_size = 12


# A verifier for the WAV file format.
# Uses the description of the WAV file format as described here:
#
# https://sites.google.com/site/musicgapi/technical-documents/wav-file-format
# http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
def unpack_wav(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a WAV file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []

    # a list of valid WAV chunk FourCC, plus a few non-standard ones
    # such as CDif and SAUR
    # SAUR: private chunk from Wavosaur:
    # https://www.wavosaur.com/forum/click-at-end-of-sounds-t315.html
    validchunkfourcc = set([b'LGWV', b'bext', b'cue ', b'data', b'fact',
                            b'fmt ', b'inst', b'labl', b'list', b'ltxt',
                            b'note', b'plst', b'smpl', b'CDif', b'SAUR',
                            b'chna', b'junk', b'axml', b'iXML', b'_PMX'])
    unpackres = unpack_riff(fileresult, scanenvironment, offset, unpackdir, validchunkfourcc, 'WAV', b'WAVE')
    if unpackres['status']:
        # see if any data chunks were found at all
        if b'data' not in unpackres['offsets']:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no data chunk found'}
            return {'status': False, 'error': unpackingerror}

        # see if any fmt chunks were found at all
        if b'fmt ' not in unpackres['offsets']:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no fmt chunk found'}
            return {'status': False, 'error': unpackingerror}
        # first a sanity check for the 'fmt' chunk
        if len(unpackres['offsets'][b'fmt ']) != 1:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'multiple fmt chunks'}
            return {'status': False, 'error': unpackingerror}
        # open the file for reading
        checkfile = open(filename_full, 'rb')

        # seek to just after the fmt chunk id
        checkfile.seek(offset + unpackres['offsets'][b'fmt '][0] + 4)
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid fmt chunk'}
            return {'status': False, 'error': unpackingerror}

        fmtsize = int.from_bytes(checkbytes, byteorder='little')
        if fmtsize not in [16, 18, 40]:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid fmt chunk size'}
            return {'status': False, 'error': unpackingerror}

        # format code, skip
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no format code'}
            return {'status': False, 'error': unpackingerror}

        # number of channels
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no data for number of channels'}
            return {'status': False, 'error': unpackingerror}
        numberofchannels = int.from_bytes(checkbytes, byteorder='little')

        # sampling rate
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no data for sampling rate'}
            return {'status': False, 'error': unpackingerror}
        samplingrate = int.from_bytes(checkbytes, byteorder='little')

        # data rate
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no data for data rate'}
            return {'status': False, 'error': unpackingerror}
        datarate = int.from_bytes(checkbytes, byteorder='little')

        # data block size
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no data for data block size'}
            return {'status': False, 'error': unpackingerror}
        datablocksize = int.from_bytes(checkbytes, byteorder='little')

        # bits per sample
        checkbytes = checkfile.read(2)
        if len(checkbytes) != 2:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'no data for data block size'}
            return {'status': False, 'error': unpackingerror}
        bitspersample = int.from_bytes(checkbytes, byteorder='little')

        if fmtsize != 16:
            # extension size
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'no data for extension size'}
                return {'status': False, 'error': unpackingerror}
            extensionsize = int.from_bytes(checkbytes, byteorder='little')

        # extra sanity checks, from:
        # http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
        if fmtsize == 16:
            # data rate = sampling rate * datablocksize
            if datarate != samplingrate * datablocksize:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'wrong value for data rate'}
                return {'status': False, 'error': unpackingerror}

        # close the file again
        checkfile.close()

        labels = unpackres['labels']
        if offset == 0 and unpackres['length'] == filesize:
            labels += ['wav', 'audio']
        for result in unpackres['filesandlabels']:
            unpackedfilesandlabels.append((result, ['wav', 'audio', 'unpacked']))
        return {'status': True, 'length': unpackres['length'],
                'filesandlabels': unpackedfilesandlabels, 'labels': labels}
    return {'status': False, 'error': unpackres['error']}

unpack_wav.signatures = {'wav': b'WAVE'}
unpack_wav.offset = 8
unpack_wav.minimum_size = 12


# An unpacker for RIFF. This is a helper method used by unpackers for:
# * WebP
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


# JPEG
# https://www.w3.org/Graphics/JPEG/
#
# ITU T.81 https://www.w3.org/Graphics/JPEG/itu-t81.pdf
# appendix B describes the format in great detail, especially
# figure B.16
#
# https://en.wikipedia.org/wiki/JPEG#Syntax_and_structure
# also has an extensive list of the markers
def unpack_jpeg(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a JPEG file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # open the file and skip the SOI magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+2)
    unpackedsize += 2

    # then further process the frame according to B.2.1
    # After SOI there are optional tables/miscellaneous (B.2.4)
    # These are defined in B.2.4.*. Marker values are in B.1
    # JPEG is in big endian order (B.1.1.1)

    # DQT, DHT, DAC, DRI, COM
    tablesmiscmarkers = set([b'\xff\xdb', b'\xff\xc4', b'\xff\xcc',
                             b'\xff\xdd', b'\xff\xfe'])

    # RST0-7
    rstmarkers = set([b'\xff\xd0', b'\xff\xd1', b'\xff\xd2', b'\xff\xd3',
                      b'\xff\xd4', b'\xff\xd5', b'\xff\xd6', b'\xff\xd7'])

    # JPEG extension markers -- are these actually being used by someone?
    jpegextmarkers = set([b'\xff\xc8', b'\xff\xf0', b'\xff\xf1', b'\xff\xf2',
                          b'\xff\xf3', b'\xff\xf4', b'\xff\xf5', b'\xff\xf6',
                          b'\xff\xf7', b'\xff\xf8', b'\xff\xf9', b'\xff\xfa',
                          b'\xff\xfb', b'\xff\xfc', b'\xff\xfd'])

    # APP0-n (16 values)
    appmarkers = set([b'\xff\xe0', b'\xff\xe1', b'\xff\xe2', b'\xff\xe3',
                      b'\xff\xe4', b'\xff\xe5', b'\xff\xe6', b'\xff\xe7',
                      b'\xff\xe8', b'\xff\xe9', b'\xff\xea', b'\xff\xeb',
                      b'\xff\xec', b'\xff\xed', b'\xff\xee', b'\xff\xef'])

    # start of frame markers
    startofframemarkers = set([b'\xff\xc0', b'\xff\xc1', b'\xff\xc2',
                               b'\xff\xc3', b'\xff\xc5', b'\xff\xc6',
                               b'\xff\xc7', b'\xff\xc9', b'\xff\xca',
                               b'\xff\xcb', b'\xff\xcd', b'\xff\xce',
                               b'\xff\xcf'])

    # keep track of whether or not a frame can be restarted
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
            # extract the length of the table or app marker.
            # this includes the 2 bytes of the length field itself
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
                # DRI
                oldoffset = checkfile.tell()
                checkbytes = checkfile.read(2)
                restartinterval = int.from_bytes(checkbytes, byteorder='big')
                if restartinterval != 0:
                    restart = True
                checkfile.seek(oldoffset)
            elif marker == b'\xff\xdb':
                # DQT, not present for lossless JPEG by definition (B.2.4.1)
                oldoffset = checkfile.tell()
                # check Pq and Tq
                checkbytes = checkfile.read(1)
                pqtq = ord(checkbytes)
                pq = pqtq >> 4
                if pq not in [0, 1]:
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
                # APP0, TODO
                oldoffset = checkfile.tell()
                checkbytes = checkfile.read(5)
                checkfile.seek(oldoffset)
            elif marker == b'\xff\xe1':
                # APP1, EXIF and friends
                # EXIF could have a thumbnail, TODO
                oldoffset = checkfile.tell()
                checkbytes = checkfile.read(5)
                checkfile.seek(oldoffset)

            # skip over the section
            checkfile.seek(misctablelength-2, os.SEEK_CUR)
            unpackedsize += misctablelength-2
        else:
            break

    # the abbreviated syntax is not widely used, so do not allow it
    allowabbreviated = False

    if allowabbreviated:
        # There *could* be an EOI marker here and it would be
        # a valid JPEG according to section B.5, although not
        # all markers would be allowed.
        if checkbytes == b'\xff\xd9':
            if seenmarkers == set():
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no tables present, needed for abbreviated syntax'}
                return {'status': False, 'error': unpackingerror}
            # according to B.5 DAC and DRI are not allowed in this syntax.
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

            # else carve the file
            outfile_rel = os.path.join(unpackdir, "unpacked.jpg")
            outfile_full = scanenvironment.unpack_path(outfile_rel)

            # create the unpacking directory
            os.makedirs(unpackdir_full, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
            outfile.close()
            unpackedfilesandlabels.append((outfile_rel, ['graphics', 'jpeg', 'unpacked']))
            checkfile.close()
            return {'status': True, 'length': unpackedsize, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

    ishierarchical = False

    # there could be a DHP segment here according to section B.3,
    # but only one in the entire image
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

        # skip over the section
        checkfile.seek(sectionlength-2, os.SEEK_CUR)
        unpackedsize += sectionlength-2

        # and make sure that there are already a few bytes read
        checkbytes = checkfile.read(2)
        if not len(checkbytes) == 2:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for table/misc'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 2

    # now there could be multiple frames, starting with optional
    # misc/tables again.
    while True:
        framerestart = restart
        while True:
            if checkbytes in tablesmiscmarkers or checkbytes in appmarkers:
                isdri = False
                if checkbytes == b'\xff\xdd':
                    isdri = True
                # extract the length of the table or app marker.
                # this includes the 2 bytes of the length field itself
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

                # skip over the section
                checkfile.seek(misctablelength-2, os.SEEK_CUR)
                unpackedsize += misctablelength-2
                checkbytes = checkfile.read(2)

                # and read the next few bytes
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2
            else:
                break

        # check if this is EXP (only in hierarchical syntax)
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

            # skip over the section
            checkfile.seek(misctablelength-2, os.SEEK_CUR)
            unpackedsize += misctablelength-2

            # and read the next two bytes
            checkbytes = checkfile.read(2)
            if not len(checkbytes) == 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for table/misc'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2

        # after the tables/misc and possibly EXP there should be
        # a frame header (B.2.2) with a SOF (start of frame) marker
        if checkbytes in startofframemarkers:
            # extract the length of the frame
            # this includes the 2 bytes of the length field itself
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
            # skip over the section
            checkfile.seek(misctablelength-2, os.SEEK_CUR)
            unpackedsize += misctablelength-2
        else:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'invalid value for start of frame'}
            return {'status': False, 'error': unpackingerror}

        # This is followed by at least one scan header,
        # optionally preceded by more tables/misc
        while True:
            if eofseen:
                break
            # optionally preceded by more tables/misc
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
                    # Extract the length of the table or app marker.
                    # This includes the 2 bytes of the length field itself
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

                    # skip over the section
                    checkfile.seek(misctablelength-2, os.SEEK_CUR)
                    unpackedsize += misctablelength-2
                else:
                    break

            # RST: no data, so simply ignore, but immediately
            # skip to more of the raw data.
            isrestart = False
            if checkbytes in rstmarkers:
                isrestart = True

            # DNL (section B.2.5)
            if checkbytes == b'\xff\xdc':
                # extract the length of the DNL
                # this includes the 2 bytes of the length field itself
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
                # skip over the section
                checkfile.seek(headerlength-3, os.SEEK_CUR)
                unpackedsize += headerlength - 3

                # and read two bytes
                checkbytes = checkfile.read(2)
                if not len(checkbytes) == 2:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for table/misc'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 2

            # the SOS (start of scan) header
            if checkbytes == b'\xff\xda':
                # extract the length of the start of scan header
                # this includes the 2 bytes of the length field itself
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

                # the number of image components, can only be 1-4
                checkbytes = checkfile.read(1)
                numberimagecomponents = ord(checkbytes)
                if numberimagecomponents not in [1, 2, 3, 4]:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid value for number of image components'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 1

                # the header length = 6+2* number of image components
                if headerlength != 6+2*numberimagecomponents:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'invalid value for number of image components or start of scan header length'}
                    return {'status': False, 'error': unpackingerror}

                # skip over the section
                checkfile.seek(headerlength-3, os.SEEK_CUR)
                unpackedsize += headerlength - 3
            else:
                if not isrestart:
                    if checkbytes != b'\xff\xd9':
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize,
                                          'fatal': False,
                                          'reason': 'invalid value for start of scan'}
                        return {'status': False, 'error': unpackingerror}
                    eofseen = True
                    continue

            # now read the image data in chunks to search for
            # JPEG markers (section B.1.1.2)
            # This is not fully fool proof: if data from the
            # entropy coded segment (ECS) is missing, or if data
            # has been inserted or changed in the ECS. The only
            # way to verify this is to reimplement it, or to run
            # it through an external tool or library such as pillow.
            readsize = 100
            while True:
                oldpos = checkfile.tell()
                checkbytes = checkfile.read(readsize)
                if checkbytes == b'':
                    break
                # check if 0xff can be found in the data. If so, then it
                # is either part of the entropy coded data (and followed
                # by 0x00), or a valid JPEG marker, or bogus data.
                if b'\xff' in checkbytes:
                    startffpos = 0
                    fffound = False
                    while True:
                        ffpos = checkbytes.find(b'\xff', startffpos)
                        if ffpos == -1:
                            break
                        # if 0xff is the last byte, bail out
                        if oldpos + ffpos == filesize - 1:
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
                                # check for SOS
                                if checkbytes[ffpos:ffpos+2] == b'\xff\xda':
                                    checkfile.seek(oldpos + ffpos)
                                    fffound = True
                                    break
                                # check for DNL
                                if checkbytes[ffpos:ffpos+2] == b'\xff\xdc':
                                    checkfile.seek(oldpos + ffpos)
                                    fffound = True
                                    break
                                # check for EOI
                                if checkbytes[ffpos:ffpos+2] == b'\xff\xd9':
                                    checkfile.seek(oldpos + ffpos + 2)
                                    eofseen = True
                                    fffound = True
                                    break

                    # set unpacked size to whatever data was read
                    unpackedsize = checkfile.tell() - offset

                    # a valid marker was found, so break out of the loop
                    if fffound:
                        break
                else:
                    unpackedsize = checkfile.tell() - offset
                if checkfile.tell() == filesize:
                    break
                checkfile.seek(-1, os.SEEK_CUR)

        # end of the image, so break out of the loop
        if eofseen:
            break

    if offset == 0 and unpackedsize == filesize:
        # now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except OSError:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid JPEG data according to PIL'}
            return {'status': False, 'error': unpackingerror}
        except PIL.Image.DecompressionBombError:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'JPEG too large according to PIL'}
            return {'status': False, 'error': unpackingerror}
        checkfile.close()

        labels.append('graphics')
        labels.append('jpeg')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file
    outfile_rel = os.path.join(unpackdir, "unpacked.jpg")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    # open as read only
    outfile = open(outfile_full, 'rb')

    # now load the file into PIL as an extra sanity check
    try:
        testimg = PIL.Image.open(outfile)
        testimg.load()
        testimg.close()
        outfile.close()
    except OSError:
        outfile.close()
        os.unlink(outfile_full)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid JPEG data according to PIL'}
        return {'status': False, 'error': unpackingerror}

    unpackedfilesandlabels.append((outfile_rel, ['jpeg', 'graphics', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_jpeg.signatures = {'jpeg': b'\xff\xd8'}


# SGI file format
# https://media.xiph.org/svt/SGIIMAGESPEC
def unpack_sgi(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a SGI image file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize - offset < 512:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for SGI header'}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename_full, 'rb')
    # skip over the magic
    checkfile.seek(offset+2)
    unpackedsize += 2

    # next the storage byte
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

    # next the bytes per pixel channel
    checkbytes = checkfile.read(1)
    bytesperpixel = ord(checkbytes)
    if bytesperpixel not in [1, 2]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for BPC'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # next the dimensions. The only allowed values are 1, 2, 3
    checkbytes = checkfile.read(2)
    dimensions = int.from_bytes(checkbytes, byteorder='big')
    if dimensions not in [1, 2, 3]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for dimensions'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # next xsize, ysize and zsize
    checkbytes = checkfile.read(2)
    xsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    checkbytes = checkfile.read(2)
    ysize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    checkbytes = checkfile.read(2)
    zsize = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    # pinmin and pinmax
    checkbytes = checkfile.read(4)
    pinmin = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    checkbytes = checkfile.read(4)
    pinmax = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # 4 bytes of dummy data, always 0x00
    checkbytes = checkfile.read(4)
    if not checkbytes == b'\x00' * 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for dummy bytes in header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # image name, NUL terminated
    checkbytes = checkfile.read(80)
    imagename = checkbytes.split(b'\x00')[0]
    unpackedsize += 80

    # colormap, can be 0, 1, 2, 3
    checkbytes = checkfile.read(4)
    colormap = int.from_bytes(checkbytes, byteorder='big')
    if colormap not in [0, 1, 2, 3]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for colormap'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # last 404 bytes of the header should be 0x00
    checkfile.seek(offset+108)
    checkbytes = checkfile.read(404)
    if checkbytes != b'\x00' * 404:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong value for dummy bytes in header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 404

    if storageformat == 'verbatim':
        # if storage format is verbatim then an image basically
        # header + (width + height + depth * bytes per pixel)
        imagelength = 512 + xsize * ysize * zsize * bytesperpixel
        if imagelength > filesize - offset:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough image data'}
            return {'status': False, 'error': unpackingerror}
        if offset == 0 and imagelength == filesize:
            # now load the file into PIL as an extra sanity check
            try:
                testimg = PIL.Image.open(checkfile)
                testimg.load()
                testimg.close()
            except OSError:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid SGI according to PIL'}
                return {'status': False, 'error': unpackingerror}
            checkfile.close()

            labels.append('sgi')
            labels.append('graphics')
            return {'status': True, 'length': imagelength, 'labels': labels,
                    'filesandlabels': unpackedfilesandlabels}

        # Carve the image.
        # first reset the file pointer
        checkfile.seek(offset)

        # in case a name was recorded in the file and it
        # is not the name given by pnmtosgi use the recorded
        # name of the file. Otherwise use a default name.
        if len(imagename) != 0 and imagename.decode() != "no name":
            outfile_rel = os.path.join(unpackdir, imagename.decode())
        else:
            outfile_rel = os.path.join(unpackdir, "unpacked.sgi")
        outfile_full = scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory
        os.makedirs(unpackdir_full, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), checkfile.fileno(), offset, imagelength)
        outfile.close()
        checkfile.close()

        # reopen as read only
        outfile = open(outfile_full, 'rb')

        # now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(outfile)
            testimg.load()
            testimg.close()
            outfile.close()
        except OSError:
            outfile.close()
            os.unlink(outfile_full)
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid SGI according to PIL'}
            return {'status': False, 'error': unpackingerror}

        unpackedfilesandlabels.append((outfile_rel, ['sgi', 'graphics', 'unpacked']))
        return {'status': True, 'length': imagelength, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # now unpack the LRE format
    # There should be two tables: starttab and lengthtab
    # store the table with offsets
    starttab = {}
    for n in range(0, ysize*zsize):
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
    for n in range(0, ysize*zsize):
        checkbytes = checkfile.read(4)
        if not len(checkbytes) == 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough bytes for RLE length table'}
            return {'status': False, 'error': unpackingerror}
        lengthtabentry = int.from_bytes(checkbytes, byteorder='big')

        # check if the data is outside of the file
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

    # Carve the image.
    # first reset the file pointer
    checkfile.seek(offset)
    outfile_rel = os.path.join(unpackdir, "unpacked.sgi")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['sgi', 'graphics', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# https://media.xiph.org/svt/SGIIMAGESPEC
unpack_sgi.signatures = {'sgi': b'\x01\xda'}
unpack_sgi.minimum_size = 512


# Derived from specifications linked at:
# https://en.wikipedia.org/wiki/Audio_Interchange_File_Format
#
# AIFF-C:
# https://web.archive.org/web/20071219035740/http://www.cnpbagwell.com/aiff-c.txt
#
# Test files in any recent Python 3 distribution in Lib/test/audiodata/
def unpack_aiff(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve an AIFF file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}

    if filesize - offset < 12:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Too small for AIFF or AIFF-C file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = 0
    checkfile = open(filename_full, 'rb')
    # skip over the header
    checkfile.seek(offset+4)
    checkbytes = checkfile.read(4)
    chunkdatasize = int.from_bytes(checkbytes, byteorder='big')

    # check if the file has enough bytes to be a valid AIFF or AIFF-C
    if offset + chunkdatasize + 8 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'chunk size bigger than file'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    checkbytes = checkfile.read(4)

    if checkbytes not in [b'AIFF', b'AIFC']:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong form type'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    if checkbytes == b'AIFF':
        aifftype = 'aiff'
    else:
        aifftype = 'aiff-c'

    # keep track of which chunk names have been seen, as a few are
    # mandatory.
    chunknames = set()

    # then read the respective chunks
    while checkfile.tell() < offset + 8 + chunkdatasize:
        chunkid = checkfile.read(4)
        if len(chunkid) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for chunk id'}
            return {'status': False, 'error': unpackingerror}
        # store the name of the chunk, as a few chunk names are mandatory
        chunknames.add(chunkid)
        unpackedsize += 4

        # read the size of the chunk
        checkbytes = checkfile.read(4)
        if len(chunkid) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for chunk'}
            return {'status': False, 'error': unpackingerror}
        chunksize = int.from_bytes(checkbytes, byteorder='big')
        # chunk sizes should be even, so add a padding byte if necessary
        if chunksize % 2 != 0:
            chunksize += 1
        # check if the chunk isn't outside of the file
        if checkfile.tell() + chunksize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'declared chunk size outside file'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4
        checkfile.seek(chunksize, os.SEEK_CUR)
        unpackedsize += chunksize

    # chunks "COMM" and "SSND" are mandatory
    if b'COMM' not in chunknames:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Mandatory chunk \'COMM\' not found.'}
        return {'status': False, 'error': unpackingerror}
    if b'SSND' not in chunknames:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Mandatory chunk \'SSND\' not found.'}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels += ['audio', 'aiff', aifftype]
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked-aiff")
    outfile_full = scanenvironment.unpack_path(outfile_rel)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['audio', 'aiff', 'unpacked', aifftype]))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_aiff.signatures = {'aiff': b'FORM'}
unpack_aiff.minimum_size = 12


# https://www.fileformat.info/format/sunraster/egff.htm
# This is not a perfect catch and Only some raster files
# might be labeled as such.
def unpack_sunraster(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a Sun raster image file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # header has 8 fields, each 4 bytes
    if filesize - offset < 32:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip over the header
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+4)
    unpackedsize += 4

    # skip width
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # skip height
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # skip depth
    checkfile.seek(4, os.SEEK_CUR)
    unpackedsize += 4

    # length without header and colormap, can be 0
    checkbytes = checkfile.read(4)
    ras_length = int.from_bytes(checkbytes, byteorder='big')
    if ras_length == 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'raster files with length 0 defined not supported'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # check type. Typical values are 0, 1, 2, 3, 4, 5 and 0xffff
    checkbytes = checkfile.read(4)
    ras_type = int.from_bytes(checkbytes, byteorder='big')
    if ras_type not in [0, 1, 2, 3, 4, 5, 0xffff]:
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

    # check the color map type. Typical values are 0, 1, 2
    checkbytes = checkfile.read(4)
    ras_maptype = int.from_bytes(checkbytes, byteorder='big')
    if ras_maptype not in [0, 1, 2]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unknown color map type field'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # length of colormap
    checkbytes = checkfile.read(4)
    ras_maplength = int.from_bytes(checkbytes, byteorder='big')

    # check if the header + length of data
    # + length of color map are inside the file
    if 32 + offset + ras_maplength + ras_length > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for raster file'}
        return {'status': False, 'error': unpackingerror}

    # skip over the rest
    unpackedsize += 4 + ras_maplength + ras_length

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('sun raster')
        labels.append('raster')
        labels.append('graphics')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # Carve the image.
    # first reset the file pointer
    checkfile.seek(offset)
    outfile_rel = os.path.join(unpackdir, "unpacked.rast")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['sun raster', 'raster', 'graphics', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

# https://www.fileformat.info/format/sunraster/egff.htm
unpack_sunraster.signatures = {'sunraster': b'\x59\xa6\x6a\x95'}
unpack_sunraster.minimum_size = 32


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


# Specifications (10.1.2.01) can be found on the Adobe site:
# https://wwwimages2.adobe.com/content/dam/acom/en/devnet/flv/video_file_format_spec_v10_1.pdf
# in Appendix E
def unpack_flv(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and/or carve a FLV file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    labels = []
    unpackingerror = {}
    unpackedfilesandlabels = []
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    unpackedsize = 0

    # First check if the file size is 9 bytes or more.
    # If not, then it is not a valid FLV file
    # FLV 10.1.2.01, E.2
    if filesize - offset < 9:
        unpackingerror = {'offset': offset,
                          'reason': 'fewer than 9 bytes',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    checkfile = open(filename_full, 'rb')
    # skip over the magic
    checkfile.seek(offset+3)
    unpackedsize += 3

    # then the file version, always 0x01
    checkbytes = checkfile.read(1)
    if checkbytes != b'\x01':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'wrong file version',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # then the type flags, do some sanity checks
    typeflags = ord(checkfile.read(1))
    if typeflags >> 1 & 1 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'wrong value for TypeFlags',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    if typeflags >> 3 != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'wrong value for TypeFlags',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # then the size of the header, should be at least 9
    checkbytes = checkfile.read(4)
    sizeofheader = int.from_bytes(checkbytes, byteorder='big')
    if sizeofheader < 9:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'wrong size header',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    if offset + sizeofheader > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'not enough bytes for header',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    # now skip over the header
    checkfile.seek(offset + sizeofheader)
    unpackedsize = sizeofheader

    # then the tags (FLV 10.1.2.01, E.3)
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'not enough bytes for tag',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    previoustagsize = int.from_bytes(checkbytes, byteorder='big')
    if previoustagsize != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'wrong previous tag size',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    # remember if any data was unpacked. This is important to
    # know in case there is trailing data, as FLV does not have
    # a clear trailer.
    dataunpacked = False

    while True:
        tagstart = checkfile.tell()
        checkbytes = checkfile.read(1)
        isfiltered = False
        if len(checkbytes) != 1:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'not enough bytes for tag',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        # highest two bits should be 0
        if ord(checkbytes) & 192 != 0:
            if dataunpacked:
                unpackedsize = tagstart - offset
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'reserved bits not 0',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        if ord(checkbytes) & 32 == 1:
            isfiltered = True
        tagtype = ord(checkbytes) & 31
        unpackedsize += 1

        # then the data size
        checkbytes = checkfile.read(3)
        if len(checkbytes) != 3:
            if dataunpacked:
                unpackedsize = tagstart - offset
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'not enough bytes for tag datasize',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        tagdatasize = int.from_bytes(checkbytes, byteorder='big')
        # tag cannot be outside of file
        if tagstart + 11 + tagdatasize > filesize:
            if dataunpacked:
                unpackedsize = tagstart - offset
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'reason':
                              'tag cannot be outside of file',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

        # then skip the time stamp information
        checkfile.seek(4, os.SEEK_CUR)

        # and read the streamid
        checkbytes = checkfile.read(3)
        if len(checkbytes) != 3:
            if dataunpacked:
                unpackedsize = tagstart - offset
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'not enough bytes for tag datasize',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        streamid = int.from_bytes(checkbytes, byteorder='big')
        if streamid != 0:
            if dataunpacked:
                unpackedsize = tagstart - offset
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'stream id not 0',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}

        # then skip a number of bytes
        checkfile.seek(tagdatasize, os.SEEK_CUR)
        unpackedsize += tagdatasize

        tagend = checkfile.tell()
        # then size of last tag
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            if dataunpacked:
                unpackedsize = tagstart - offset
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'not enough bytes for tag size',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        previoustagsize = int.from_bytes(checkbytes, byteorder='big')
        if previoustagsize != tagend - tagstart:
            if dataunpacked:
                unpackedsize = tagstart - offset
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'reason': 'stored tag size does not match tag size',
                              'fatal': False}
            return {'status': False, 'error': unpackingerror}
        dataunpacked = True
        unpackedsize = tagend - offset + 4
        if checkfile.tell() == filesize:
            break

    if not dataunpacked:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'reason': 'no data could be unpacked',
                          'fatal': False}
        return {'status': False, 'error': unpackingerror}

    if offset == 0 and filesize == unpackedsize:
        checkfile.close()
        labels.append('flv')
        labels.append('video')
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # Carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.flv")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()
    outlabels = ['flv', 'video', 'unpacked']
    unpackedfilesandlabels.append((outfile_rel, outlabels))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_flv.signatures = {'flv': b'FLV'}
unpack_flv.minimum_size = 9


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


# a seemingly proprietary file format from 3D Studio Max. There is not
# much to extract, but at least the size of the file can be verified.
# This analysis was based on just a few samples found inside the
# firmware of an Android phone made by LG Electronics.
def unpack_xg3d(fileresult, scanenvironment, offset, unpackdir):
    '''Verify XG files (3D Studio Max format)'''
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

    # header seems to be at least 70 bytes
    if filesize - offset < 70:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip to offset 29, as that
    # is where the file size can be found.
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+29)
    unpackedsize += 29

    # read two bytes to find the file size. Perhaps this
    # value starts earlier and four bytes are needed instead?
    checkbytes = checkfile.read(2)
    recordedfilesize = int.from_bytes(checkbytes, byteorder='little')

    # data cannot be outside of the file
    if recordedfilesize - offset > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for XG3D data'}
        return {'status': False, 'error': unpackingerror}

    # don't support carving right now
    if recordedfilesize - offset < filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'carving not supported'}
        return {'status': False, 'error': unpackingerror}

    # the same value also appears at offset 0x21?
    # check the tool string, which should be
    # "3D Studio Max XG Exporter" followed by a number
    checkfile.seek(offset + 0x25)
    checkbytes = checkfile.read(25)
    if checkbytes != b'3D Studio Max XG Exporter':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not a valid 3D Studio Max string'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = recordedfilesize

    if offset == 0 and recordedfilesize == filesize:
        labels.append('xg3d')
        labels.append('3D Studio Max')
        labels.append('resource')

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

unpack_xg3d.signatures = {'xg3d': b'XG3D'}


# https://www.khronos.org/opengles/sdk/tools/KTX/file_format_spec/
def unpack_ktx11(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/carve Khronos KTX texture files'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    if filesize - offset < 64:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the offset
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+12)
    unpackedsize += 12

    # endianness
    endianness = 'little'
    checkbytes = checkfile.read(4)
    if checkbytes != b'\x01\x02\x03\x04':
        if checkbytes != b'\x04\x03\x02\x01':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'wrong endianness bytes'}
            return {'status': False, 'error': unpackingerror}
        endianness = 'big'
    unpackedsize += 4

    # gltype, either compressed or something else
    checkbytes = checkfile.read(4)
    gltype = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    if gltype == 0:
        compressed = True
    else:
        compressed = False

    # gltypesize
    checkbytes = checkfile.read(4)
    gltypesize = int.from_bytes(checkbytes, byteorder=endianness)

    # sanity check: if compressed, then gltypesize must be 1
    if compressed and gltypesize != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for glTypeSize'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # glformat
    checkbytes = checkfile.read(4)
    glformat = int.from_bytes(checkbytes, byteorder=endianness)

    # sanity check: if compressed, then glformat must be 0
    if compressed and glformat != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for glFormat'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # glinternalformat
    checkbytes = checkfile.read(4)
    glinternalformat = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    # glbaseinternalformat
    checkbytes = checkfile.read(4)
    glbaseinternalformat = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    # pixel width
    checkbytes = checkfile.read(4)
    pixelwidth = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    # pixel height
    checkbytes = checkfile.read(4)
    pixelheight = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    # pixel depth
    checkbytes = checkfile.read(4)
    pixeldepth = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    # number of array elements
    checkbytes = checkfile.read(4)
    numberofarrayelements = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    # number of faces
    checkbytes = checkfile.read(4)
    numberoffaces = int.from_bytes(checkbytes, byteorder=endianness)
    if numberoffaces not in [1, 6]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'wrong value for numberOfFaces'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # number of mipmap levels
    checkbytes = checkfile.read(4)
    numberofmipmaplevels = int.from_bytes(checkbytes, byteorder=endianness)
    unpackedsize += 4

    # bytes of key value data
    checkbytes = checkfile.read(4)
    bytesofkeyvaluedata = int.from_bytes(checkbytes, byteorder=endianness)
    if offset + unpackedsize + bytesofkeyvaluedata > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for key/value data'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # read the key/value data
    bytestoread = bytesofkeyvaluedata
    while bytestoread > 0:
        checkbytes = checkfile.read(4)
        keyvaluesize = int.from_bytes(checkbytes, byteorder=endianness)
        if checkfile.tell() + keyvaluesize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for key/value data'}
            return {'status': False, 'error': unpackingerror}
        bytestoread -= 4

        if keyvaluesize > bytestoread:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for key/value data'}
            return {'status': False, 'error': unpackingerror}
        keyvalue = checkfile.read(keyvaluesize)
        bytestoread -= keyvaluesize

        # padding
        paddingsize = 0
        if keyvaluesize % 4 != 0:
            paddingsize = 4 - keyvaluesize % 4
            checkbytes = checkfile.read(paddingsize)
            if checkbytes != paddingsize * b'\x00':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'wrong value for padding bytes'}
                return {'status': False, 'error': unpackingerror}
        bytestoread -= paddingsize

    unpackedsize += bytesofkeyvaluedata

    # then process the mipmaplevels
    if numberofmipmaplevels == 0:
        nrlevels = 1
    elif glinternalformat in [0x8B90, 0x8B91, 0x8B92, 0x8B93, 0x8B94,
                              0x8B95, 0x8B96, 0x8B97, 0x8B98, 0x8B99]:
        # GL_PALETTE_*, so set to 1
        nrlevels = 1
    else:
        nrlevels = numberofmipmaplevels

    for i in range(0, nrlevels):
        checkbytes = checkfile.read(4)
        if len(checkbytes) != 4:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for mipmap level size'}
            return {'status': False, 'error': unpackingerror}

        # image size per face, so multiply with number of faces
        imagesize = numberoffaces*int.from_bytes(checkbytes, byteorder=endianness)
        if checkfile.tell() + imagesize > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for mipmap image'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 4

        # skip image size bytes
        checkfile.seek(imagesize, os.SEEK_CUR)
        unpackedsize += imagesize

        # padding
        paddingsize = 0
        if imagesize % 4 != 0:
            paddingsize = 4 - imagesize % 4
            checkbytes = checkfile.read(paddingsize)
            if checkbytes != paddingsize * b'\x00':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'wrong value for padding bytes'}
                return {'status': False, 'error': unpackingerror}
        unpackedsize += paddingsize

    if offset == 0 and unpackedsize == filesize:
        checkfile.close()
        labels.append('ktx')
        labels.append('graphics')

        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.ktx")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((outfile_rel, ['graphics', 'ktx', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_ktx11.signatures = {'ktx11': b'\xabKTX 11\xbb\r\n\x1a\n'}
unpack_ktx11.pretty = 'ktx'
unpack_ktx11.minimum_size = 64


# Try to read Photoshop PSD files.
# Specifications:
#
# https://www.adobe.com/devnet-apps/photoshop/fileformatashtml/
def unpack_psd(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Photoshop PSD file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # header + length field of color mode data section is 30
    if offset + 30 > filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset + 4)
    unpackedsize += 4

    # version, always 1
    checkbytes = checkfile.read(2)
    version = int.from_bytes(checkbytes, byteorder='big')
    if version != 1:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong version number'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # reserved "must be zero"
    checkbytes = checkfile.read(6)
    reserved = int.from_bytes(checkbytes, byteorder='big')
    if reserved != 0:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'reserved bytes not 0 '}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 6

    # number of channels, range 1-56
    checkbytes = checkfile.read(2)
    numberofchannels = int.from_bytes(checkbytes, byteorder='big')
    if numberofchannels < 1 or numberofchannels > 56:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong number of channels'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # image height, range 1-30,000
    checkbytes = checkfile.read(4)
    imageheight = int.from_bytes(checkbytes, byteorder='big')
    if imageheight < 1 or imageheight > 30000:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid image height'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # image width, range 1-30,000
    checkbytes = checkfile.read(4)
    imagewidth = int.from_bytes(checkbytes, byteorder='big')
    if imagewidth < 1 or imagewidth > 30000:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid image width'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # depth
    checkbytes = checkfile.read(2)
    imagedepth = int.from_bytes(checkbytes, byteorder='big')
    if imagedepth not in [1, 8, 16, 32]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid image depth'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # color mode
    checkbytes = checkfile.read(2)
    colormode = int.from_bytes(checkbytes, byteorder='big')
    if colormode not in [0, 1, 2, 3, 4, 7, 8, 9]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid color mode'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # color mode data section
    checkbytes = checkfile.read(4)
    colormodelength = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # skip any data from the color mode data section if defined
    if colormodelength > 0:
        checkfile.seek(colormodelength, os.SEEK_CUR)
        unpackedsize += colormodelength

    # images resources section
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for images resources section'}
        return {'status': False, 'error': unpackingerror}
    resourceslength = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    if checkfile.tell() + resourceslength > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for images resources section'}
        return {'status': False, 'error': unpackingerror}

    # skip the resources now. TODO: process
    if resourceslength > 0:
        checkfile.seek(resourceslength, os.SEEK_CUR)
        unpackedsize += resourceslength

    # layer and mask information section
    checkbytes = checkfile.read(4)
    if len(checkbytes) != 4:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for layer and mask information section'}
        return {'status': False, 'error': unpackingerror}
    layersectionlength = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    if checkfile.tell() + layersectionlength > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for layer and mask information section'}
        return {'status': False, 'error': unpackingerror}
    if layersectionlength > 0:
        checkfile.seek(layersectionlength, os.SEEK_CUR)
        unpackedsize += layersectionlength

    # image pixel data
    checkbytes = checkfile.read(2)
    if len(checkbytes) != 2:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for pixel data compression method'}
        return {'status': False, 'error': unpackingerror}
    compressionmethod = int.from_bytes(checkbytes, byteorder='big')
    if compressionmethod not in [0, 1, 2, 3]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'invalid pixel data compression method'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 2

    # only support compression method 1 right now
    if compressionmethod not in [0, 1]:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unsupported pixel data compression method'}
        return {'status': False, 'error': unpackingerror}

    if compressionmethod == 0:
        totbytes = numberofchannels * imageheight * imagewidth
        if checkfile.tell() + totbytes > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                              'reason': 'not enough data for raw mode'}
            return {'status': False, 'error': unpackingerror}
    elif compressionmethod == 1:
        totbytes = 0
        for i in range(imageheight * numberofchannels):
            checkbytes = checkfile.read(2)
            if len(checkbytes) != 2:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for RLE byte count'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 2
            bytecounts = int.from_bytes(checkbytes, byteorder='big')
            totbytes += bytecounts
        if checkfile.tell() + totbytes > filesize:
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for RLE encoded data'}
            return {'status': False, 'error': unpackingerror}
    unpackedsize += totbytes

    if offset == 0 and unpackedsize == filesize:
        # now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except OSError:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid PSD data according to PIL'}
            return {'status': False, 'error': unpackingerror}
        checkfile.close()
        labels += ['psd', 'graphics']
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.psd")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()

    # reopen as read only
    outfile = open(outfile_full, 'rb')

    # now load the file into PIL as an extra sanity check
    try:
        testimg = PIL.Image.open(outfile)
        testimg.load()
        testimg.close()
        outfile.close()
    except OSError:
        outfile.close()
        os.unlink(outfile_full)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid PSD data according to PIL'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['graphics', 'psd', 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_psd.signatures = {'psd': b'8BPS'}
unpack_psd.minimum_size = 30


# Read PPM files, PBM files and PGM files
# man 5 ppm
# man 5 pgm
def unpack_pnm(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a 'raw' PNM file (PPM, PGM, PBM)'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # open the file and read the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset)
    checkbytes = checkfile.read(2)
    if checkbytes == b'P6':
        pnmtype = 'ppm'
    elif checkbytes == b'P5':
        pnmtype = 'pgm'
    elif checkbytes == b'P4':
        pnmtype = 'pbm'
    unpackedsize += 2

    # then there should be whitespace
    seenwhitespace = False
    while True:
        checkbytes = checkfile.read(1)
        if checkbytes == b'':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for header whitespace'}
            return {'status': False, 'error': unpackingerror}
        if chr(ord(checkbytes)) in string.whitespace:
            seenwhitespace = True
        else:
            if seenwhitespace:
                checkfile.seek(-1, os.SEEK_CUR)
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'no whitespace in header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    # width, in ASCII digital
    widthbytes = b''
    seenint = False
    while True:
        checkbytes = checkfile.read(1)
        if checkbytes == b'':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for width'}
            return {'status': False, 'error': unpackingerror}
        if checkbytes == b'#':
            # comment, read until newline is found
            unpackedsize += 1
            while True:
                checkbytes = checkfile.read(1)
                if checkbytes == b'':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize,
                                      'fatal': False,
                                      'reason': 'not enough data for width'}
                    return {'status': False, 'error': unpackingerror}
                unpackedsize += 1
                if checkbytes == b'\n':
                    break
            continue
        try:
            int(checkbytes)
            widthbytes += checkbytes
            seenint = True
        except ValueError:
            if seenint:
                checkfile.seek(-1, os.SEEK_CUR)
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'no integer in header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
    width = int(widthbytes)

    # then more whitespace
    seenwhitespace = False
    while True:
        checkbytes = checkfile.read(1)
        if checkbytes == b'':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for header whitespace'}
            return {'status': False, 'error': unpackingerror}
        if chr(ord(checkbytes)) in string.whitespace:
            seenwhitespace = True
        else:
            if seenwhitespace:
                checkfile.seek(-1, os.SEEK_CUR)
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'no whitespace in header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1

    # height, in ASCII digital
    heightbytes = b''
    seenint = False
    while True:
        checkbytes = checkfile.read(1)
        if checkbytes == b'':
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'not enough data for height'}
            return {'status': False, 'error': unpackingerror}
        try:
            int(checkbytes)
            heightbytes += checkbytes
            seenint = True
        except ValueError:
            if seenint:
                checkfile.seek(-1, os.SEEK_CUR)
                break
            checkfile.close()
            unpackingerror = {'offset': offset+unpackedsize,
                              'fatal': False,
                              'reason': 'no integer in header'}
            return {'status': False, 'error': unpackingerror}
        unpackedsize += 1
    height = int(heightbytes)

    if pnmtype != 'pbm':
        # then more whitespace
        seenwhitespace = False
        while True:
            checkbytes = checkfile.read(1)
            if checkbytes == b'':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for header whitespace'}
                return {'status': False, 'error': unpackingerror}
            if chr(ord(checkbytes)) in string.whitespace:
                seenwhitespace = True
            else:
                if seenwhitespace:
                    checkfile.seek(-1, os.SEEK_CUR)
                    break
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no whitespace in header'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 1

        # maximum color value, in ASCII digital
        maxbytes = b''
        seenint = False
        while True:
            checkbytes = checkfile.read(1)
            if checkbytes == b'':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'not enough data for maximum color value'}
                return {'status': False, 'error': unpackingerror}
            try:
                int(checkbytes)
                maxbytes += checkbytes
                seenint = True
            except ValueError:
                if seenint:
                    checkfile.seek(-1, os.SEEK_CUR)
                    break
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize,
                                  'fatal': False,
                                  'reason': 'no integer in header'}
                return {'status': False, 'error': unpackingerror}
            unpackedsize += 1
        maxvalue = int(maxbytes)

    # single whitespace
    checkbytes = checkfile.read(1)
    if checkbytes == b'':
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header whitespace'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 1

    if pnmtype == 'pbm':
        # each row is width bits
        rowlength = width//8
        if width % 8 != 0:
            rowlength += 1
        lendatabytes = rowlength * height
    else:
        if maxvalue < 256:
            lendatabytes = width * height
            if pnmtype == 'ppm':
                lendatabytes = lendatabytes * 3
        else:
            lendatabytes = width * height * 2
            if pnmtype == 'ppm':
                lendatabytes = lendatabytes * 3
    if offset + unpackedsize + lendatabytes > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for raster'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize += lendatabytes

    if offset == 0 and unpackedsize == filesize:
        # now load the file into PIL as an extra sanity check
        try:
            testimg = PIL.Image.open(checkfile)
            testimg.load()
            testimg.close()
        except OSError:
            checkfile.close()
            if pnmtype == 'pgm':
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid PGM data according to PIL'}
            elif pnmtype == 'ppm':
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid PPM data according to PIL'}
            elif pnmtype == 'pbm':
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid PBM data according to PIL'}
            return {'status': False, 'error': unpackingerror}
        checkfile.close()
        labels += [pnmtype, 'graphics']
        return {'status': True, 'length': unpackedsize, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked." + pnmtype)
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, unpackedsize)
    outfile.close()

    # reopen as read only
    outfile = open(outfile_full, 'rb')

    # now load the file into PIL as an extra sanity check
    try:
        testimg = PIL.Image.open(outfile)
        testimg.load()
        testimg.close()
        outfile.close()
    except (OSError, ValueError):
        outfile.close()
        os.unlink(outfile_full)
        if pnmtype == 'pgm':
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid PGM data according to PIL'}
        elif pnmtype == 'ppm':
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid PPM data according to PIL'}
        elif pnmtype == 'pbm':
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'invalid PBM data according to PIL'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    unpackedfilesandlabels.append((outfile_rel, ['graphics', pnmtype, 'unpacked']))
    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_pnm.signatures = {'ppm': b'P6', 'pgm': b'P5', 'pbm': b'P4'}


# https://github.com/mapsforge/mapsforge/blob/master/docs/Specification-Binary-Map-File.md
def unpack_mapsforge(fileresult, scanenvironment, offset, unpackdir):
    '''Verify/carve a Mapsforge binary mape file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # header is at least 64 bytes
    if offset + 64 > filesize:
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}

    # open the file and skip the magic
    checkfile = open(filename_full, 'rb')
    checkfile.seek(offset+20)

    # header size
    checkbytes = checkfile.read(4)
    header_size = int.from_bytes(checkbytes, byteorder='big')
    if offset + header_size + 20 > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 4

    # file version
    checkbytes = checkfile.read(4)
    file_version = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # map size
    checkbytes = checkfile.read(8)
    map_size = int.from_bytes(checkbytes, byteorder='big')
    if offset + map_size > filesize:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize,
                          'fatal': False,
                          'reason': 'not enough data for header'}
        return {'status': False, 'error': unpackingerror}
    unpackedsize += 8

    # creation date
    checkbytes = checkfile.read(8)
    creation_date = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 8

    # bounding box
    checkbytes = checkfile.read(4)
    min_lat = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    checkbytes = checkfile.read(4)
    min_lon = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    checkbytes = checkfile.read(4)
    max_lat = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    checkbytes = checkfile.read(4)
    max_lon = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 4

    # tile size
    checkbytes = checkfile.read(2)
    tile_size = int.from_bytes(checkbytes, byteorder='big')
    unpackedsize += 2

    if offset == 0 and map_size == filesize:
        labels.append('mapsforge')
        checkfile.close()
        return {'status': True, 'length': map_size, 'labels': labels,
                'filesandlabels': unpackedfilesandlabels}

    # else carve the file. It is anonymous, so just give it a name
    outfile_rel = os.path.join(unpackdir, "unpacked.map")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)
    outfile = open(outfile_full, 'wb')
    os.sendfile(outfile.fileno(), checkfile.fileno(), offset, map_size)
    outfile.close()
    checkfile.close()

    unpackedfilesandlabels.append((outfile_rel, ['mapsforge', 'unpacked']))
    return {'status': True, 'length': map_size, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_mapsforge.signatures = {'mapsforge': b'mapsforge binary OSM'}
unpack_mapsforge.minimum_size = 64
