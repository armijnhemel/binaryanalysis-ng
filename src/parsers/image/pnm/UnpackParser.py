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

# Read PPM files, PBM files and PGM files
# man 5 ppm
# man 5 pgm

import os
import pathlib
import string
import tempfile

import PIL.Image

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class PnmUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'P6'),
        (0, b'P5'),
        (0, b'P4')
    ]
    pretty_name = 'pnm'

    def parse(self):
        # read the first few bytes to see which kind of file it possibly is
        self.infile.seek(0)
        checkbytes = self.infile.read(2)

        if checkbytes == b'P6':
            self.pnmtype = 'ppm'
        elif checkbytes == b'P5':
            self.pnmtype = 'pgm'
        elif checkbytes == b'P4':
            self.pnmtype = 'pbm'

        # then there should be one or more whitespace characters
        seenwhitespace = False
        while True:
            checkbytes = self.infile.read(1)
            check_condition(len(checkbytes) == 1, "not enough data for header whitespace")

            if chr(ord(checkbytes)) in string.whitespace:
                seenwhitespace = True
            else:
                if seenwhitespace:
                    self.infile.seek(-1, os.SEEK_CUR)
                    break
                raise UnpackParserException("no whitespace in header")

        # width, in ASCII digital, possibly first preceded by a comment
        widthbytes = b''
        seenint = False
        while True:
            checkbytes = self.infile.read(1)
            check_condition(len(checkbytes) == 1, "not enough data for width")

            if checkbytes == b'#':
                # comment, read until newline is found
                while True:
                    checkbytes = self.infile.read(1)
                    check_condition(len(checkbytes) == 1, "not enough data for width")
                    if checkbytes == b'\n':
                        break
                continue
            try:
                int(checkbytes)
                widthbytes += checkbytes
                seenint = True
            except ValueError as e:
                if seenint:
                    self.infile.seek(-1, os.SEEK_CUR)
                    break
                raise UnpackParserException(e.args)

        width = int(widthbytes)

        # then there should be one or more whitespace characters
        seenwhitespace = False
        while True:
            checkbytes = self.infile.read(1)
            check_condition(len(checkbytes) == 1, "not enough data for header whitespace")

            if chr(ord(checkbytes)) in string.whitespace:
                seenwhitespace = True
            else:
                if seenwhitespace:
                    self.infile.seek(-1, os.SEEK_CUR)
                    break
                raise UnpackParserException("no whitespace in header")

        # height, in ASCII digital
        heightbytes = b''
        seenint = False
        while True:
            checkbytes = self.infile.read(1)
            check_condition(len(checkbytes) == 1, "not enough data for height")

            try:
                int(checkbytes)
                heightbytes += checkbytes
                seenint = True
            except ValueError as e:
                if seenint:
                    self.infile.seek(-1, os.SEEK_CUR)
                    break
                raise UnpackParserException(e.args)
        height = int(heightbytes)

        if self.pnmtype != 'pbm':
            # then more whitespace
            seenwhitespace = False
            while True:
                checkbytes = self.infile.read(1)
                check_condition(len(checkbytes) == 1, "not enough data for header whitespace")

                if chr(ord(checkbytes)) in string.whitespace:
                    seenwhitespace = True
                else:
                    if seenwhitespace:
                        self.infile.seek(-1, os.SEEK_CUR)
                        break
                    raise UnpackParserException("no whitespace in header")

            # maximum color value, in ASCII digital
            maxbytes = b''
            seenint = False
            while True:
                checkbytes = self.infile.read(1)
                check_condition(len(checkbytes) == 1, "not enough data for maximum color value")
                try:
                    int(checkbytes)
                    maxbytes += checkbytes
                    seenint = True
                except ValueError as e:
                    if seenint:
                        self.infile.seek(-1, os.SEEK_CUR)
                        break
                    raise UnpackParserException(e.args)
            maxvalue = int(maxbytes)

        # single whitespace
        checkbytes = self.infile.read(1)
        check_condition(len(checkbytes) == 1, "not enough data for header whitespace")
        check_condition(chr(ord(checkbytes)) in string.whitespace,
                        "invalid whitespace")

        if self.pnmtype == 'pbm':
            # each row is width bits
            rowlength = width//8
            if width % 8 != 0:
                rowlength += 1
            len_data_bytes = rowlength * height
        else:
            if maxvalue < 256:
                len_data_bytes = width * height
                if self.pnmtype == 'ppm':
                    len_data_bytes = len_data_bytes * 3
            else:
                len_data_bytes = width * height * 2
                if self.pnmtype == 'ppm':
                    len_data_bytes = len_data_bytes * 3

        check_condition(self.infile.tell() + len_data_bytes <= self.fileresult.filesize,
                        "not enough data for raster")

        self.unpacked_size = self.infile.tell() + len_data_bytes
        # use PIL as an extra sanity check

        if self.unpacked_size == self.fileresult.filesize:
            # now load the file using PIL as an extra sanity check
            # although this doesn't seem to do a lot.
            try:
                testimg = PIL.Image.open(self.infile)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
            except ValueError as e:
                raise UnpackParserException(e.args)
            except ZeroDivisionError as e:
                raise UnpackParserException(e.args)
        else:
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

            # reopen as read only
            pnm_file = open(temporary_file[1], 'rb')
            try:
                testimg = PIL.Image.open(pnm_file)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
            except ValueError as e:
                raise UnpackParserException(e.args)
            except ZeroDivisionError as e:
                raise UnpackParserException(e.args)
            finally:
                pnm_file.close()
                os.unlink(temporary_file[1])

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['graphics', self.pnmtype]
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
