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
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# JPEG
# https://www.w3.org/Graphics/JPEG/
#
# ITU T.81 https://www.w3.org/Graphics/JPEG/itu-t81.pdf
# appendix B describes the format in great detail, especially
# figure B.16
#
# https://en.wikipedia.org/wiki/JPEG#Syntax_and_structure
# also has an extensive list of the markers


import os
import tempfile

import PIL.Image

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

# DQT, DHT, DAC, DRI, COM
TABLES_MISC_MARKERS = set([b'\xff\xdb', b'\xff\xc4', b'\xff\xcc',
                           b'\xff\xdd', b'\xff\xfe'])

# RST0-7
RST_MARKERS = set([b'\xff\xd0', b'\xff\xd1', b'\xff\xd2', b'\xff\xd3',
                   b'\xff\xd4', b'\xff\xd5', b'\xff\xd6', b'\xff\xd7'])

# JPEG extension markers -- are these actually being used by someone?
JPEG_EXT_MARKERS = set([b'\xff\xc8', b'\xff\xf0', b'\xff\xf1', b'\xff\xf2',
                        b'\xff\xf3', b'\xff\xf4', b'\xff\xf5', b'\xff\xf6',
                        b'\xff\xf7', b'\xff\xf8', b'\xff\xf9', b'\xff\xfa',
                        b'\xff\xfb', b'\xff\xfc', b'\xff\xfd'])

# APP0-n (16 values)
APP_MARKERS = set([b'\xff\xe0', b'\xff\xe1', b'\xff\xe2', b'\xff\xe3',
                   b'\xff\xe4', b'\xff\xe5', b'\xff\xe6', b'\xff\xe7',
                   b'\xff\xe8', b'\xff\xe9', b'\xff\xea', b'\xff\xeb',
                   b'\xff\xec', b'\xff\xed', b'\xff\xee', b'\xff\xef'])

# start of frame markers
START_OF_FRAME_MARKERS = set([b'\xff\xc0', b'\xff\xc1', b'\xff\xc2',
                              b'\xff\xc3', b'\xff\xc5', b'\xff\xc6',
                              b'\xff\xc7', b'\xff\xc9', b'\xff\xca',
                              b'\xff\xcb', b'\xff\xcd', b'\xff\xce',
                              b'\xff\xcf'])


class JpegUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xff\xd8')
    ]
    pretty_name = 'jpeg'

    def parse(self):
        # skip the SOI magic
        self.infile.seek(2)

        # then further process the frame according to B.2.1
        # After SOI there are optional tables/miscellaneous (B.2.4)
        # These are defined in B.2.4.*. Marker values are in B.1
        # JPEG is in big endian order (B.1.1.1)

        # keep track of whether or not a frame can be restarted
        restart = False
        eofseen = False

        seen_markers = set()
        while True:
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2, "not enough data for table/misc")

            if checkbytes in TABLES_MISC_MARKERS or checkbytes in APP_MARKERS:
                # store the marker
                marker = checkbytes
                seen_markers.add(marker)

                # extract the length of the table or app marker.
                # this includes the 2 bytes of the length field itself
                checkbytes = self.infile.read(2)
                check_condition(len(checkbytes) == 2, "not enough data for table/misc length field")

                misctablelength = int.from_bytes(checkbytes, byteorder='big')
                check_condition(self.infile.tell() + misctablelength - 2 <= self.fileresult.filesize,
                                "table outside of file")

                if marker == b'\xff\xdd':
                    # DRI
                    oldoffset = self.infile.tell()
                    checkbytes = self.infile.read(2)
                    check_condition(len(checkbytes) == 2, "not enough data for DRI")
                    restartinterval = int.from_bytes(checkbytes, byteorder='big')
                    if restartinterval != 0:
                        restart = True
                    self.infile.seek(oldoffset)

                elif marker == b'\xff\xdb':
                    # DQT, not present for lossless JPEG by definition (B.2.4.1)
                    oldoffset = self.infile.tell()

                    # check Pq and Tq
                    checkbytes = self.infile.read(1)
                    check_condition(len(checkbytes) == 1, "not enough data for DQT")
                    pqtq = ord(checkbytes)
                    pq = pqtq >> 4
                    check_condition(pq in [0, 1], "invalid DQT value")
                    tq = pqtq & 15
                    check_condition(tq < 4, "invalid DQT value")

                    self.infile.seek(oldoffset)
                elif marker == b'\xff\xe0':
                    # APP0, TODO
                    oldoffset = self.infile.tell()
                    checkbytes = self.infile.read(5)
                    check_condition(len(checkbytes) == 5, "not enough data for APP0")
                    self.infile.seek(oldoffset)
                elif marker == b'\xff\xe1':
                    # APP1, EXIF and friends
                    # EXIF could have a thumbnail, TODO
                    oldoffset = self.infile.tell()
                    checkbytes = self.infile.read(5)
                    check_condition(len(checkbytes) == 5, "not enough data for APP1")
                    self.infile.seek(oldoffset)

                # skip over the section
                self.infile.seek(misctablelength-2, os.SEEK_CUR)
            else:
                break

        '''
        # the abbreviated syntax is not widely used, so do not allow it
        # but keep the code for now
        allowabbreviated = False

        if allowabbreviated:
            # There *could* be an EOI marker here and it would be
            # a valid JPEG according to section B.5, although not
            # all markers would be allowed.
            if checkbytes == b'\xff\xd9':
                check_condition(seen_markers != set(),
                                "no tables present, needed for abbreviated syntax")

                # according to B.5 DAC and DRI are not allowed in this syntax.
                check_condition(b'\xff\xcc' not in seen_markers and b'\xff\xdd' not in seen_markers,
                                "DAC and/or DRI not allowed in abbreviated syntax")

                self.unpacked_size = self.infile.tell()
                return
        '''

        ishierarchical = False

        # there could be a DHP segment here according to section B.3,
        # but only one in the entire image
        if checkbytes == b'\xff\xde':
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for table/misc length field")

            sectionlength = int.from_bytes(checkbytes, byteorder='big')

            check_condition(self.infile.tell() + sectionlength - 2 <= self.fileresult.filesize,
                            "table outside of file")

            ishierarchical = True

            # skip over the section
            self.infile.seek(sectionlength-2, os.SEEK_CUR)

            # and make sure that a few bytes are already read
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2, "not enough data for table/misc")

        # now there could be multiple frames, starting with optional
        # misc/tables again.
        while True:
            framerestart = restart
            while True:
                if checkbytes in TABLES_MISC_MARKERS or checkbytes in APP_MARKERS:
                    isdri = False
                    if checkbytes == b'\xff\xdd':
                        isdri = True
                    # extract the length of the table or app marker.
                    # this includes the 2 bytes of the length field itself
                    checkbytes = self.infile.read(2)
                    check_condition(len(checkbytes) == 2,
                                    "not enough data for table/misc length field")

                    misctablelength = int.from_bytes(checkbytes, byteorder='big')
                    check_condition(self.infile.tell() + misctablelength - 2 <= self.fileresult.filesize,
                                    "table outside of file")

                    if isdri:
                        oldoffset = self.infile.tell()
                        checkbytes = self.infile.read(2)
                        check_condition(len(checkbytes) == 2,
                                        "not enough data for table/misc")
                        restartinterval = int.from_bytes(checkbytes, byteorder='big')
                        if restartinterval != 0:
                            framerestart = True
                        self.infile.seek(oldoffset)

                    # skip over the section
                    self.infile.seek(misctablelength-2, os.SEEK_CUR)

                    # and read the next few bytes
                    checkbytes = self.infile.read(2)
                    check_condition(len(checkbytes) == 2,
                                    "not enough data for table/misc")
                else:
                    break

            # check if this is EXP (only in hierarchical syntax)
            if checkbytes == b'\xff\xdf':
                check_condition(ishierarchical, "EXP only allowed in hierarchical syntax")

                checkbytes = self.infile.read(2)
                check_condition(len(checkbytes) == 2,
                                "not enough data for table/misc length field")

                misctablelength = int.from_bytes(checkbytes, byteorder='big')
                check_condition(self.infile.tell() + misctablelength - 2 <= self.fileresult.filesize,
                                "table outside of file")

                # skip over the section
                self.infile.seek(misctablelength-2, os.SEEK_CUR)

                # and read the next two bytes
                checkbytes = self.infile.read(2)
                check_condition(len(checkbytes) == 2,
                                "not enough data for table/misc")

            # after the tables/misc (and possibly EXP) there should be
            # a frame header (B.2.2) with a SOF (start of frame) marker
            check_condition(checkbytes in START_OF_FRAME_MARKERS,
                            "invalid value for start of frame")

            # extract the length of the frame
            # this includes the 2 bytes of the length field itself
            checkbytes = self.infile.read(2)
            check_condition(len(checkbytes) == 2,
                            "not enough data for table/misc length field")

            misctablelength = int.from_bytes(checkbytes, byteorder='big')
            check_condition(self.infile.tell() + misctablelength - 2 <= self.fileresult.filesize,
                            "table outside of file")

            # skip over the section
            self.infile.seek(misctablelength-2, os.SEEK_CUR)

            # This is followed by at least one scan header,
            # optionally preceded by more tables/misc
            while True:
                if eofseen:
                    break

                # optionally preceded by more tables/misc
                while True:
                    checkbytes = self.infile.read(2)
                    check_condition(len(checkbytes) == 2,
                                    "not enough data for table/misc")

                    if checkbytes in TABLES_MISC_MARKERS or checkbytes in APP_MARKERS:
                        # Extract the length of the table or app marker.
                        # This includes the 2 bytes of the length field itself
                        checkbytes = self.infile.read(2)
                        check_condition(len(checkbytes) == 2,
                                        "not enough data for table/misc length field")

                        misctablelength = int.from_bytes(checkbytes, byteorder='big')
                        check_condition(self.infile.tell() + misctablelength - 2 <= self.fileresult.filesize,
                                        "table outside of file")

                        # skip over the section
                        self.infile.seek(misctablelength-2, os.SEEK_CUR)
                    else:
                        break

                # RST: no data, so simply ignore, but immediately
                # skip to more of the raw data.
                isrestart = False
                if checkbytes in RST_MARKERS:
                    isrestart = True

                # DNL (section B.2.5)
                if checkbytes == b'\xff\xdc':
                    # extract the length of the DNL
                    # this includes the 2 bytes of the length field itself
                    checkbytes = self.infile.read(2)
                    check_condition(len(checkbytes) == 2,
                                    "not enough data for table/misc length field")

                    headerlength = int.from_bytes(checkbytes, byteorder='big')
                    check_condition(self.infile.tell() + headerlength - 2 <= self.fileresult.filesize,
                                    "start of scan outside of file")

                    # skip over the section
                    self.infile.seek(headerlength-3, os.SEEK_CUR)

                    # and read two bytes
                    checkbytes = self.infile.read(2)
                    check_condition(len(checkbytes) == 2,
                                    "not enough data for table/misc")

                # the SOS (start of scan) header
                if checkbytes == b'\xff\xda':
                    # extract the length of the start of scan header
                    # this includes the 2 bytes of the length field itself
                    checkbytes = self.infile.read(2)
                    check_condition(len(checkbytes) == 2,
                                    "not enough data for table/misc length field")

                    headerlength = int.from_bytes(checkbytes, byteorder='big')
                    check_condition(self.infile.tell() + headerlength - 2 <= self.fileresult.filesize,
                                    "start of scan outside of file")

                    # the number of image components, can only be 1-4
                    checkbytes = self.infile.read(1)
                    check_condition(len(checkbytes) == 1,
                                    "not enough data for number of image components")

                    numberimagecomponents = ord(checkbytes)
                    check_condition(numberimagecomponents in [1, 2, 3, 4],
                                    "invalid value for number of image components")

                    # the header length = 6+2* number of image components
                    check_condition(headerlength == 6+2*numberimagecomponents, 
                                    "invalid value for number of image components or start of scan header length")

                    # skip over the section
                    self.infile.seek(headerlength-3, os.SEEK_CUR)
                else:
                    if not isrestart:
                        check_condition(checkbytes == b'\xff\xd9',
                                        "invalid value for start of scan")
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
                    oldpos = self.infile.tell()
                    checkbytes = self.infile.read(readsize)
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
                            if oldpos + ffpos == self.fileresult.filesize - 1:
                                break
                            startffpos = ffpos + 1
                            if ffpos < readsize - 1:
                                if checkbytes[ffpos+1] != 0:
                                    if checkbytes[ffpos:ffpos+2] in TABLES_MISC_MARKERS or checkbytes[ffpos:ffpos+2] in APP_MARKERS:
                                        self.infile.seek(oldpos + ffpos)
                                        fffound = True
                                        break
                                    if checkbytes[ffpos:ffpos+2] in JPEG_EXT_MARKERS:
                                        self.infile.seek(oldpos + ffpos)
                                        fffound = True
                                        break
                                    if checkbytes[ffpos:ffpos+2] in RST_MARKERS:
                                        self.infile.seek(oldpos + ffpos)
                                        fffound = True
                                        break
                                    # check for SOS
                                    if checkbytes[ffpos:ffpos+2] == b'\xff\xda':
                                        self.infile.seek(oldpos + ffpos)
                                        fffound = True
                                        break
                                    # check for DNL
                                    if checkbytes[ffpos:ffpos+2] == b'\xff\xdc':
                                        self.infile.seek(oldpos + ffpos)
                                        fffound = True
                                        break
                                    # check for EOI
                                    if checkbytes[ffpos:ffpos+2] == b'\xff\xd9':
                                        self.infile.seek(oldpos + ffpos + 2)
                                        eofseen = True
                                        fffound = True
                                        break

                        # a valid marker was found, so break out of the loop
                        if fffound:
                            break
                    if self.infile.tell() == self.fileresult.filesize:
                        break
                    self.infile.seek(-1, os.SEEK_CUR)

            # end of the image, so break out of the loop
            if eofseen:
                break

        self.unpacked_size = self.infile.tell()
        if self.unpacked_size == self.fileresult.filesize:
            # now load the file using PIL as an extra sanity check
            # although this doesn't seem to do a lot.
            try:
                testimg = PIL.Image.open(self.infile)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
            except PIL.Image.DecompressionBombError as e:
                raise UnpackParserException(e.args)
        else:
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

            # reopen as read only
            jpeg_file = open(temporary_file[1], 'rb')
            try:
                testimg = PIL.Image.open(jpeg_file)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
            except PIL.Image.DecompressionBombError as e:
                raise UnpackParserException(e.args)
            finally:
                jpeg_file.close()
                os.unlink(temporary_file[1])



    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['graphics', 'jpeg']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
