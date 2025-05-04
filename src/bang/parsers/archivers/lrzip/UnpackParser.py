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

import os
import pathlib
import shutil
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import lrzip


class LrzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'LRZI')
    ]
    pretty_name = 'lrzip'

    def parse(self):
        if shutil.which('lrzip') is None:
            raise UnpackParserException("lrzip not installed")

        try:
            self.data = lrzip.Lrzip.from_io(self.infile)
            self.unpacked_size = self.infile.tell()

            # force read blocks to trigger evaluation by kaitai struct
            for rchunk in self.data.rchunks:
                # first process all blocks in stream 0
                cur_stream_header = rchunk.stream_0
                next_block_head = 0
                while cur_stream_header is not None:
                    self.unpacked_size = max(self.unpacked_size, cur_stream_header.start_position + cur_stream_header.len_data + cur_stream_header.size + next_block_head)
                    next_block_head = cur_stream_header.next_block_head
                    cur_stream_header = cur_stream_header.next

                # then process all blocks in stream 1
                cur_stream_header = rchunk.stream_1
                next_block_head = 0
                while cur_stream_header is not None:
                    self.unpacked_size = max(self.unpacked_size, cur_stream_header.start_position + cur_stream_header.len_data + cur_stream_header.size + next_block_head)
                    next_block_head = cur_stream_header.next_block_head
                    cur_stream_header = cur_stream_header.next

            # finally check if there is an md5 sum (16 bytes)
            if self.data.header.has_md5:
                self.unpacked_size += 16

        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        check_condition(self.unpacked_size <= self.infile.size, "data cannot be outside of file")

        # test unpacking here. lrzip expects the input file to be a
        # single lrzip archive and it will fail if there is data either
        # in front of the lrzip data or is trailing it. If the
        # same lrzip archive is concatened it will work (but will only
        # extract the file once).
        self.havetmpfile = False
        if not (self.offset == 0 and self.infile.size == self.unpacked_size):
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            self.havetmpfile = True
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(self.temporary_file[0]).close()

        if self.havetmpfile:
            p = subprocess.Popen(['lrzip', '-d', self.temporary_file[1], '-o', '-'],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['lrzip', '-d', self.infile.name, '-o', '-'],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if p.returncode != 0:
            if self.havetmpfile:
                os.unlink(self.temporary_file[1])
            raise UnpackParserException("lrzip failed unpacking")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.lrz':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_lrzip")
        else:
            file_path = pathlib.Path('unpacked_from_lrzip')


        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            if self.havetmpfile:
                p = subprocess.Popen(['lrzip', '-d', self.temporary_file[1], '-o', '-'],
                    stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)
            else:
                p = subprocess.Popen(['lrzip', '-d', self.infile.name, '-o', '-'],
                    stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()

            if self.havetmpfile:
                os.unlink(self.temporary_file[1])

            yield unpacked_md

    labels = ['lrzip', 'compressed']
    metadata = {}
