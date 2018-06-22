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
##
## Unpackers needing external Python libraries or other tools
##
##  1. PNG (needs PIL)
##  2. ar (needs binutils)
##  3. squashfs (needs squashfs-tools)
##  4. BMP (needs netpbm-progs)
##
## For these unpackers it has been attempted to reduce disk I/O as much as possible
## using the os.sendfile() method, as well as techniques described in this blog
## post:
##
## https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import sys, os, struct, shutil, binascii, zlib, subprocess, lzma, tarfile, stat
import tempfile, zipfile, bz2

## some external packages that are needed
import PIL.Image

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
                        ## now load the file into PIL as an extra sanity check
                        try:
                                testimg = PIL.Image.open(checkfile)
                                testimg.load()
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

                ## now load the file into PIL as an extra sanity check
                try:
                        testimg = PIL.Image.open(outfilename)
                        testimg.load()
                except:
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

        if shutil.which('bmptopnm') == None:
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'bmptopnm program not found'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        ## then reset the file pointer, read all the data and feed it
        ## to bmptopnm for validation.
        checkfile.seek(offset)
        checkbytes = checkfile.read(bmpsize)
        checkfile.close()
        p = subprocess.Popen(['bmptopnm'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate(checkbytes)
        if p.returncode != 0:
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid BMP'}
                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

        ## check if the file was the whole file
        if offset == 0 and filesize == bmpsize:
                labels.append('bmp')
                labels.append('graphics')
                return (True, filesize, unpackedfilesandlabels, labels, unpackingerror)

        ## carve the file. The data has already been read.
        outfilename = os.path.join(unpackdir, "unpacked.bmp")
        outfile = open(outfilename, 'wb')
        outfile.write(checkbytes)
        outfile.close()
        unpackedfilesandlabels.append((outfilename, ['bmp', 'graphics', 'unpacked']))
        return (True, bmpsize, unpackedfilesandlabels, labels, unpackingerror)

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

        ## Data was unpacked from the file, so the data up until now is definitely a tar,
        ## but is the rest of the file also part of the tar or of something else?
        ## Example: GNU tar tends to pad files with up to 20 blocks (512 bytes each) filled
        ## with 0x00 although this depends on the command line settings.
        ## This can be checked with GNU tar by inspecting the file with the options
        ## "itvRf" to the tar command:
        ##
        ## $ tar itvRf /path/to/tar/file
        ##
        ## These padding bytes are not read by Python's tarfile module and need to
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

                ## process everything that is not a local file header
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
                                if extrafieldlength != 0:
                                        if extrafieldlength < 4:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field in central directory'}
                                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                ## see if there is a data descriptor for regular files (this
                ## won't be set for directories)
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
                checkbytes = checkfile.read(2)
                if len(checkbytes) != 2:
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field length in local file header'}
                        return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
                extrafieldlength = int.from_bytes(checkbytes, byteorder='little')
                unpackedsize += 2
                if extrafieldlength != 0:
                        ## The extra fields are at least 4 bytes (section 4.5.1)
                        if extrafieldlength < 4:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data for extra field'}
                                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

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
                if extrafieldlength != 0:
                        extrafields = checkfile.read(extrafieldlength)
                        extrafieldcounter = 0
                        while extrafieldcounter + 4 < extrafieldlength:
                                ## section 4.6.1
                                extrafieldheaderid = int.from_bytes(extrafields[extrafieldcounter:extrafieldcounter+2], byteorder='little')
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
                                if checkbytes == b'':
                                        break
                                if datadescriptor:
                                        ddpos = checkbytes.find(b'PK\x07\x08')
                                        if ddpos != -1:
                                                if tmppos == -1:
                                                      tmppos = ddpos
                                                ddsearched = True
                                                ddfound = True
                                localheaderpos = checkbytes.find(b'PK\x03\x04')
                                if localheaderpos != -1:
                                        if tmppos == -1:
                                                tmppos = localheaderpos
                                        else:
                                                tmppos = min(localheaderpos, tmppos)
                                centraldirpos = checkbytes.find(b'PK\x01\x02')
                                if centraldirpos != -1:
                                        if tmppos == -1:
                                                tmppos = centraldirpos
                                        else:
                                                tmppos = min(centraldirpos, tmppos)
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
def unpackBzip2(filename, offset, unpackdir, temporarydirectory):
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
                        outfile.close()
                        os.unlink(os.path.join(unpackdir, outfilename))
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'File not a valid bzip2 file, use bzip2recover?'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                outfile.write(unpackeddata)
                ## there is no more compressed data
                unpackedsize += len(bz2data) - len(bz2decompressor.unused_data)
                if bz2decompressor.unused_data != b'':
                        break
                bz2data = checkfile.read(datareadsize)

        checkfile.close()
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
