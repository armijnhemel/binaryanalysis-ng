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
import tempfile

import snappy

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import snappy as kaitai_snappy


class SnappyUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xff\x06\x00\x00\x73\x4e\x61\x50\x70\x59')
    ]
    pretty_name = 'snappy_framed'

    def parse(self):
        try:
            self.data = kaitai_snappy.Snappy.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # first chunk has to be the header, even though
        # this is already covered by the signature
        check_condition(self.data.chunks[0].identifier == kaitai_snappy.Snappy.ChunkTypes.stream_identifier,
                        "invalid first chunk")

        seen_frame_identifier = False

        self.unpacked_size = 0
        for chunk in self.data.chunks:
            if chunk.is_valid:
                # check to see if there possibly is more than one stream
                # if so decompress them separately
                if chunk.identifier == kaitai_snappy.Snappy.ChunkTypes.stream_identifier:
                    if not seen_frame_identifier:
                        seen_frame_identifier = True
                    else:
                        break
                self.unpacked_size += 4 + chunk.body.len_chunk.value

        # check if the file starts at offset 0. If not, carve the
        # file first, as snappy tries to be smart and unpack
        # all concatenated snappy data in a file.
        self.havetmpfile = False

        if not (self.offset == 0 and self.infile.size == self.unpacked_size):
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            self.havetmpfile = True
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(self.temporary_file[0]).close()

        # try to decompress the snappy data
        if self.havetmpfile:
            infile = open(self.temporary_file[1], 'rb')
        else:
            infile = self.infile.infile
            infile.seek(0)

        outfile = open(os.devnull, 'wb')
        try:
            snappy.stream_decompress(infile, outfile)
        except Exception as e:
            if self.havetmpfile:
                infile.close()
                os.unlink(self.temporary_file[1])
            raise UnpackParserException(e.args)
        finally:
            outfile.close()

        if self.havetmpfile:
            infile.close()

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.sz':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_snappy")
        else:
            file_path = pathlib.Path("unpacked_from_snappy")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            if self.havetmpfile:
                infile = open(self.temporary_file[1], 'rb')
            else:
                infile = self.infile.infile
                infile.seek(0)

            snappy.stream_decompress(infile, outfile)

            if self.havetmpfile:
                infile.close()
                os.unlink(self.temporary_file[1])

            yield unpacked_md

    def calculate_unpacked_size(self):
        pass

    labels = ['snappy', 'compressed']
    metadata = {}
