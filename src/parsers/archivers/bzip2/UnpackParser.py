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


import bz2
import os
import pathlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import bzip2

class Bzip2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BZh01AY&SY'),
        (0, b'BZh11AY&SY'),
        (0, b'BZh21AY&SY'),
        (0, b'BZh31AY&SY'),
        (0, b'BZh41AY&SY'),
        (0, b'BZh51AY&SY'),
        (0, b'BZh61AY&SY'),
        (0, b'BZh71AY&SY'),
        (0, b'BZh81AY&SY'),
        (0, b'BZh91AY&SY')
    ]
    pretty_name = 'bzip2'

    def parse(self):
        try:
            self.data = bzip2.Bzip2.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # the header parsed cleanly, so test unpack the data
        # First reset the offset
        self.infile.seek(self.offset)

        # then create a bzip2 decompressor
        bz2decompressor = bz2.BZ2Decompressor()

        # incrementally read compressed data and decompress:
        # https://docs.python.org/3/library/bz2.html#incremental-de-compression

        self.unpacked_size = 0
        datareadsize = 10000000
        bz2data = self.infile.read(datareadsize)
        while bz2data != b'':
            try:
                bz2decompressor.decompress(bz2data)
            except EOFError as e:
                break
            except Exception as e:
                raise UnpackParserException(e.args)

            # there is no more compressed data
            self.unpacked_size += len(bz2data) - len(bz2decompressor.unused_data)
            if bz2decompressor.unused_data != b'':
                break
            bz2data = self.infile.read(datareadsize)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.bz2':
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_bz2")
        elif self.fileresult.filename.suffix.lower() in ['.tbz', '.tbz2', '.tb2', '.tarbz2']:
            file_path = pathlib.Path(self.fileresult.filename.stem + ".tar")
        else:
            file_path = pathlib.Path("unpacked_from_bz2")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        # First reset the offset
        self.infile.seek(self.offset)

        # then create a bzip2 decompressor
        bz2decompressor = bz2.BZ2Decompressor()

        # incrementally read compressed data and decompress:
        # https://docs.python.org/3/library/bz2.html#incremental-de-compression

        self.unpacked_size = 0
        datareadsize = 10000000
        bz2data = self.infile.read(datareadsize)
        while bz2data != b'':
            try:
                unpacked_data = bz2decompressor.decompress(bz2data)
                outfile.write(unpacked_data)
            except EOFError as e:
                break
            except Exception as e:
                raise UnpackParserException(e.args)

            # there is no more compressed data
            self.unpacked_size += len(bz2data) - len(bz2decompressor.unused_data)
            if bz2decompressor.unused_data != b'':
                break
            bz2data = self.infile.read(datareadsize)
        outfile.close()

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
        unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['bzip2', 'compressed']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
