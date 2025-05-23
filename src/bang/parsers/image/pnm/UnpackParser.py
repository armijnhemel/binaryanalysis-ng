# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

# Read PPM files, PBM files and PGM files
# man 5 ppm
# man 5 pgm

import io
import os
import string

import PIL.Image

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


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
                raise UnpackParserException(e.args) from e

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
                raise UnpackParserException(e.args) from e
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
                    raise UnpackParserException(e.args) from e
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

        check_condition(self.infile.tell() + len_data_bytes <= self.infile.size,
                        "not enough data for raster")

        self.unpacked_size = self.infile.tell() + len_data_bytes
        # use PIL as an extra sanity check

        if self.unpacked_size == self.infile.size:
            # now load the file using PIL as an extra sanity check
            # although this doesn't seem to do a lot.
            try:
                testimg = PIL.Image.open(self.infile)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args) from e
            except ValueError as e:
                raise UnpackParserException(e.args) from e
            except ZeroDivisionError as e:
                raise UnpackParserException(e.args) from e
        else:
            # load the PNM/PPM/PBM data into memory
            self.infile.seek(0)
            pnm_bytes = io.BytesIO(self.infile.read(self.unpacked_size))

            # test in PIL
            try:
                testimg = PIL.Image.open(pnm_bytes)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args) from e
            except ValueError as e:
                raise UnpackParserException(e.args) from e
            except ZeroDivisionError as e:
                raise UnpackParserException(e.args) from e
            except PIL.Image.DecompressionBombError as e:
                raise UnpackParserException(e.args) from e

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    @property
    def labels(self):
        labels = ['graphics', self.pnmtype]
        return labels

    metadata = {}
