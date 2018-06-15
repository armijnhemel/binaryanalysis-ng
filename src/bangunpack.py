#!/usr/bin/python3

## Built in carvers/verifiers/unpackers for various formats.
##
## Copyright 2018 - Armijn Hemel
## Licensed under the terms of the GNU Affero General Public License version 3
## SPDX-License-Identifier: AGPL-3.0-only
##
## Native Python unpackers for:
##
##  1. WebP
##  2. WAV
##  3. gzip
##
## For these unpackers it has been attempted to reduce disk I/O as much as possible
## using the os.sendfile() method, as well as techniques described in this blog
## post:
##
## https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import sys, os, struct, shutil, binascii, zlib

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
