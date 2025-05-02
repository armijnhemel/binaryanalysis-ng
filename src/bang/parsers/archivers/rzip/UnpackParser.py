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

# https://rzip.samba.org/
# https://en.wikipedia.org/wiki/Rzip

import bz2
import os
import pathlib
import shutil
import subprocess

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

BZ2_SIGNATURES = [b'BZh01AY&SY', b'BZh11AY&SY', b'BZh21AY&SY',
                  b'BZh31AY&SY', b'BZh41AY&SY', b'BZh51AY&SY',
                  b'BZh61AY&SY', b'BZh71AY&SY', b'BZh81AY&SY',
                  b'BZh91AY&SY']


class RzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'RZIP')
    ]
    pretty_name = 'rzip'

    def parse(self):
        check_condition(shutil.which('rzip') is not None,
                        "rzip program not found")

        # skip the header
        self.infile.seek(4)

        # then read the major version
        buf = self.infile.read(1)
        check_condition(ord(buf) <= 2, "invalid rzip major version %d" % ord(buf))

        # then read the minor version
        buf = self.infile.read(1)
        check_condition(len(buf) == 1, "not enough data for minor version")

        # then read the size of the uncompressed data
        buf = self.infile.read(4)
        check_condition(len(buf) == 4, "not enough data for minor version")
        uncompressed_size = int.from_bytes(buf, byteorder='big')

        # check if there actually is bzip2 compressed data.
        bzip2_header_found = False
        while True:
            while True:
                oldpos = self.infile.tell()
                checkbytes = self.infile.read(200)
                if len(checkbytes) == 0:
                    break
                bz2pos = checkbytes.find(b'BZh')
                if bz2pos != -1:
                    if checkbytes[bz2pos:bz2pos+10] in BZ2_SIGNATURES:
                        bz2pos += oldpos
                        bzip2_header_found = True
                        break
                if len(checkbytes) > 4:
                    self.infile.seek(-4, os.SEEK_CUR)

            # no bzip2 data was found, so it is not a valid rzip file
            check_condition(bzip2_header_found, "no valid bzip2 header found")

            bz2decompressor = bz2.BZ2Decompressor()
            self.infile.seek(bz2pos)

            # incrementally read compressed data and decompress:
            # https://docs.python.org/3/library/bz2.html#incremental-de-compression
            datareadsize = 10000000
            bz2data = self.infile.read(datareadsize)
            bz2size = 0
            while bz2data != b'':
                try:
                    bz2decompressor.decompress(bz2data)
                except EOFError as e:
                    break
                except Exception as e:
                    raise UnpackParserException(e.args)

                # there is no more compressed data
                bz2size += len(bz2data) - len(bz2decompressor.unused_data)
                if bz2decompressor.unused_data != b'':
                    break
                bz2data = self.infile.read(datareadsize)

            self.infile.seek(bz2pos + bz2size)

            self.unpacked_size = self.infile.tell()

            # check if there could be another block with bzip2 data
            # the data between the bzip2 blocks is 13 bytes, see
            # rzip source code, file: stream.c, function: fill_buffer()
            if self.infile.size - (bz2pos + bz2size) < 13:
                break

            self.infile.seek(13, os.SEEK_CUR)
            checkbytes = self.infile.read(3)
            if checkbytes != b'BZh':
                break

            self.infile.seek(-3, os.SEEK_CUR)

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.rz':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_rzip")
        else:
            file_path = pathlib.Path("unpacked_from_rzip")

        with meta_directory.unpack_regular_file_no_open(file_path) as (unpacked_md, outfile):
            p = subprocess.Popen(['rzip', '-k', '-d', meta_directory.file_path, '-o', outfile],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            (outputmsg, errormsg) = p.communicate()
            yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['compressed', 'rzip']
    metadata = {}
