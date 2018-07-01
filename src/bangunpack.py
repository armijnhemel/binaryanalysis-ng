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
## 13. XAR
## 14. ISO9660 (including RockRidge and zisofs)
## 15. lzip
## 16. WOFF
## 17. TrueType fonts
## 18. OpenType fonts
## 19. Vim swap files (whole file only)
## 20. Android sparse data image
##
## Unpackers needing external Python libraries or other tools
##
##  1. PNG/APNG (needs PIL)
##  2. ar (needs binutils)
##  3. squashfs (needs squashfs-tools)
##  4. BMP (needs netpbm-progs)
##  5. GIF (needs PIL)
##  6. JPEG (needs PIL)
##
## For these unpackers it has been attempted to reduce disk I/O as much as possible
## using the os.sendfile() method, as well as techniques described in this blog
## post:
##
## https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews

import sys, os, struct, shutil, binascii, zlib, subprocess, lzma, tarfile, stat
import tempfile, zipfile, bz2, collections, math

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

        ## a minimal GIF file is 6 + 6 + 6 + 1 + 19
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
        ## now load the file into PIL as an extra sanity check
        try:
                testimg = PIL.Image.open(outfilename)
                testimg.load()
        except:
                checkfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid GIF data according to PIL'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)
        checkfile.close()
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
##
## IEEE P1281 Draft Version 1.12
## http://www.ymi.com/ymi/sites/default/files/pdf/Systems%20Use%20P1281.pdf
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
        while True:
                checkbytes = checkfile.read(2048)
                if len(checkbytes) != 2048:
                        checkfile.close()
                        unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'not enough bytes'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                ## each volume descriptor has a type and an identifier (ECMA 119, section 8.1)
                if checkbytes[1:6] != b'CD001':
                        checkfile.close()
                        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'wrong identifier'}
                        return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                volumedescriptoroffset = checkfile.tell()

                ## volume descriptor type
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

                        if int.from_bytes(checkbytes[128:130], byteorder='little') != int.from_bytes(checkbytes[130:132], byteorder='big'):
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'endian mismatch'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)
                        ## ECMA 119, 8.4.12
                        logical_size = int.from_bytes(checkbytes[128:130], byteorder='little')

                        ## sanity check: the ISO image cannot be outside of the file
                        if offset + volume_space_size * logical_size > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
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
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## sanity check: the ISO image cannot be outside of the declared size of the file
                        if extent_location * logical_size > volume_space_size * logical_size:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## extent size (ECMA 119, 9.1.4)
                        root_directory_extent_length = int.from_bytes(root_directory_entry[10:14], byteorder='little')
                        ## sanity check: the ISO image cannot be outside of the file
                        if offset + extent_location * logical_size + root_directory_extent_length > filesize:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                        ## sanity check: the ISO image cannot be outside of the declared size of the file
                        if extent_location * logical_size + root_directory_extent_length > volume_space_size * logical_size:
                                checkfile.close()
                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
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

                        ## recursively walk all entries in the directory structure
                        ## add: location of the extent, the size of the extent, location where to unpack, name
                        extents = collections.deque()
                        extents.append((extent_location, root_directory_extent_length, unpackdir, ''))

                        ## keep track of which extents need to be moved.
                        extenttomove = {}
                        relocatedextents = set()
                        plparent = {}

                        firstextentprocessed = False

                        ## in case there is rock ridge or zisofs the first
                        ## directory entry in the first extent will contain
                        ## the SP System Use entry, which specifies how many
                        ## bytes to skip (IEEE P1281, section 5.3)
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
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                        ## sanity check: the ISO image cannot be outside of the declared size of the file
                                        if extent_location * logical_size > volume_space_size * logical_size:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
                                                return (False, 0, unpackedfilesandlabels, labels, unpackingerror)

                                        ## extent size (ECMA 119, 9.1.4)
                                        directory_extent_length = int.from_bytes(directory_entry[10:14], byteorder='little')
                                        ## sanity check: the ISO image cannot be outside of the file
                                        if offset + extent_location * logical_size + directory_extent_length > filesize:
                                                checkfile.close()
                                                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False, 'reason': 'not enough data'}
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
                                                                        ## no need to process sparse file
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
                                                                pass
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
                unpackedsize += 2048

                if haveterminator:
                        break

        checkfile.close()

        ## there should always be a terminator. If not, then it is not
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

        ## now load the file into PIL as an extra sanity check
        try:
                testimg = PIL.Image.open(outfilename)
                testimg.load()
        except:
                checkfile.close()
                os.unlink(outfilename)
                unpackingerror = {'offset': offset, 'fatal': False, 'reason': 'invalid JPEG data according to PIL'}
                return (False, unpackedsize, unpackedfilesandlabels, labels, unpackingerror)

        unpackedfilesandlabels.append((outfilename, ['jpeg', 'graphics', 'unpacked']))
        checkfile.close()
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

        res = unpackFont(filename, offset, unpackdir, temporarydirectory, requiredtables, 'ttf', 'TrueType')
        return res

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
