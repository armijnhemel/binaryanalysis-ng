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

# https://en.wikipedia.org/wiki/SREC_(file_format)
# It is assumed that only files that are completely text
# files can be SREC files.

import os
import pathlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class SrecUnpackParser(UnpackParser):
    extensions = ['.srec']
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'srec'

    def parse(self):
        bytes_read = 0

        # open the file again, but then in text mode
        srec_file = open(self.infile.name, 'r')

        # read the lines of the data, until either EOF
        # or until the end of the srec data has been reached
        data_unpacked = False
        end_of_srec = False

        record_types = set()
        unpacked = 0

        # in case there is an error store the error message
        # and process it later. This cannot be done with
        # check_condition as this doesn't close srec_file
        error_msg = ''

        # A line has six fields:
        #
        # 1. start: S
        # 2. record type (one digit)
        # 3. byte count (two characters) - includes the bytes for the address
        # 4. address (four / six / eight characters)
        # 5. data ((byte count - bytes for address) * 2 characters)
        # 6. checksum (2 characters)
        #
        # minimum length for a line is:
        # 1 + 1 + 2 + 4 + 0 + 2 = 10
        # Each byte uses two characters. The start code
        # and record type use 1 character.
        # That means that each line MUST has an even length.

        for srec_line in srec_file:
            line = srec_line.rstrip()
            if not line.startswith('S'):
                # There could be comments starting with ';',
                # although this is discouraged.
                if line.startswith(';'):
                    if srec_file.newlines is not None:
                        unpacked += len(line) + len(srec_file.newlines)
                    else:
                        unpacked += len(line)
                    continue
                break

            if len(line) < 10 or len(line) % 2 != 0:
                break

            try:
                record_type = int(srec_line[1])
            except:
                error_msg = 'invalid SREC record type'
                break

            if record_type == 4:
                error_msg = 'reserved SREC record type'
                break

            record_types.add(record_type)

            if record_type in [7, 8, 9]:
                end_of_srec = True
                unpacked += len(line) + len(srec_file.newlines)
                break

            # next two bytes are the byte count.
            try:
                num_bytes = int.from_bytes(bytes.fromhex(line[2:4]), byteorder='big')
            except:
                break

            if num_bytes < 3:
                error_msg = 'invalid byte count'
                break

            if len(line) != 4 + num_bytes * 2:
                error_msg = 'invalid byte count'
                break

            if record_type == 0:
                # metadata
                try:
                    bytes.fromhex(line[8:8+(num_bytes-3)*2])
                except ValueError:
                    break
            elif record_type == 1:
                try:
                    bytes.fromhex(line[8:8+(num_bytes-3)*2])
                except ValueError:
                    break
            elif record_type == 2:
                try:
                    bytes.fromhex(line[10:10+(num_bytes-4)*2])
                except ValueError:
                    break
            elif record_type == 3:
                try:
                    bytes.fromhex(line[12:12+(num_bytes-5)*2])
                except ValueError:
                    break
            unpacked += len(line) + len(srec_file.newlines)

        srec_file.close()

        if error_msg != '':
            raise UnpackParserException(error_msg)

        # TODO: sanity checks for record types

        check_condition(end_of_srec and unpacked != 0, "no data unpacked")

        self.unpacked_size = unpacked


    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        out_labels = []

        if self.fileresult.filename.suffix.lower() in ['.srec']:
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_srec")
        else:
            file_path = pathlib.Path("unpacked_from_srec")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        srec_file = open(self.infile.name, 'r')

        for srec_line in srec_file:
            line = srec_line.rstrip()
            if not line.startswith('S'):
                # There could be comments
                if line.startswith(';'):
                    continue
                break

            if len(line) < 10 or len(line) % 2 != 0:
                break

            record_type = int(srec_line[1])

            if record_type == 4:
                break

            if record_type in [7, 8, 9]:
                break

            # next two bytes are the byte count.
            try:
                num_bytes = int.from_bytes(bytes.fromhex(line[2:4]), byteorder='big')
            except:
                break

            if record_type == 0:
                # metadata
                bytes.fromhex(line[8:8+(num_bytes-3)*2])
            elif record_type == 1:
                outfile.write(bytes.fromhex(line[8:8+(num_bytes-3)*2]))
            elif record_type == 2:
                outfile.write(bytes.fromhex(line[10:10+(num_bytes-4)*2]))
            elif record_type == 3:
                outfile.write(bytes.fromhex(line[12:12+(num_bytes-5)*2]))

        srec_file.close()
        outfile.close()

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files


    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['srec']

        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
