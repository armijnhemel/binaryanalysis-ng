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


import os
import pathlib
import tempfile

import snappy

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    def unpack(self):
        out_labels = []
        unpacked_files = []

        # check if the file starts at offset 0. If not, carve the
        # file first, as snappy tries to be smart and unpack
        # all concatenated snappy data in a file.
        havetmpfile = False

        if not (self.offset == 0 and self.fileresult.filesize == self.unpacked_size):
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            havetmpfile = True
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.sz':
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_snappy")
        else:
            file_path = pathlib.Path("unpacked_from_snappy")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        if havetmpfile:
            infile = open(temporary_file[1], 'rb')
        else:
            infile = self.infile.infile
            infile.seek(0)

        try:
            snappy.stream_decompress(infile, outfile)
            outfile.close()
        except Exception as e:
            outfile.close()
            if havetmpfile:
                infile.close()
                os.unlink(temporary_file[1])
            raise UnpackParserException(e.args)
            #return unpacked_files
        if havetmpfile:
            os.unlink(temporary_file[1])

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['snappy', 'compressed']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
