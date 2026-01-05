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

# https://en.wikipedia.org/wiki/Intel_HEX
# It is assumed that only files that are completely text
# files can be IHex files.

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class IhexUnpackParser(UnpackParser):
    extensions = ['.hex', '.ihex']
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'ihex'

    def parse(self):
        # open the file again, but then in text mode
        try:
            ihex_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            ihex_file.close()
            raise UnpackParserException(e.args) from e

        # read the lines of the data, until either EOF
        # or until the end of the ihex data has been reached
        data_unpacked = False
        end_of_ihex = False

        record_types = set()
        unpacked = 0

        # in case there is an error store the error message
        # and process it later. This cannot be done with
        # check_condition as this doesn't close ihex_file
        error_msg = ''

        # A line has six fields:
        #
        # 1. start: ;
        # 2. byte count (two characters)
        # 3. address (four characters)
        # 4. record type (two characters)
        # 5. data (byte count * 2 characters)
        # 6. checksum (2 characters)
        #
        # minimum length for a line is:
        # 1 + 2 + 4 + 2 + 0 + 2 = 11
        # Each byte uses two characters. The start code
        # uses 1 character.
        # That means that each line MUST has an uneven length.
        try:
            for hex_line in ihex_file:
                if not hex_line.startswith(':'):
                    # There could be comments
                    if hex_line.startswith('#'):
                        unpacked += len(hex_line)
                        continue
                    break

                line = hex_line.rstrip()

                if len(line) < 11 or len(line) % 2 != 1:
                    break

                # next two bytes are the byte count
                try:
                    num_bytes = int.from_bytes(bytes.fromhex(line[1:3]), byteorder='big')
                except:
                    break

                if len(line) - 11 != num_bytes * 2:
                    error_msg = 'invalid byte count'
                    break

                # address can be skipped
                try:
                    record_type = int.from_bytes(bytes.fromhex(line[7:9]), byteorder='big')
                except:
                    break
                if record_type > 5:
                    error_msg = 'invalid record type'
                    break

                # record type 0 is data, record type 1 is end of data
                # Other record types do not include any actual data.
                if record_type == 1:
                    if num_bytes != 0:
                        error_msg = 'invalid byte counts for record type 01'
                        break
                    end_of_ihex = True
                    unpacked += len(hex_line)
                    break
                if record_type == 0:
                    try:
                        ihexdata = bytes.fromhex(line[9:9+num_bytes*2])
                    except ValueError:
                        break
                else:
                    if record_type == 2:
                        if num_bytes != 2:
                            error_msg = 'invalid byte counts for record type 02'
                            break
                    elif record_type == 3:
                        if num_bytes != 4:
                            error_msg = 'invalid byte counts for record type 03'
                            break
                    if record_type == 4:
                        if num_bytes != 2:
                            error_msg = 'invalid byte counts for record type 04'
                            break
                    elif record_type == 5:
                        if num_bytes != 4:
                            error_msg = 'invalid byte counts for record type 05'
                            break
                    record_types.add(record_type)
                unpacked += len(hex_line)
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            ihex_file.close()

        if error_msg != '':
            raise UnpackParserException(error_msg)

        # not all record types can appear at the same time
        if record_types != set():
            if 4 in record_types or 5 in record_types:
                check_condition(2 not in record_types, "invalid combination of record types")
                check_condition(3 not in record_types, "invalid combination of record types")
        check_condition(end_of_ihex and unpacked != 0, "no data unpacked")
        self.unpacked_size = unpacked

    def unpack(self, meta_directory):
        if meta_directory.file_path.suffix.lower() in ['.hex', '.ihex']:
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_ihex")
        else:
            file_path = pathlib.Path("unpacked_from_ihex")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            ihex_file = open(self.infile.name, 'r')
            for hex_line in ihex_file:
                line = hex_line.rstrip()
                if not line.startswith(':'):
                    # There could be comments
                    if line.startswith('#'):
                        continue
                    break

                if len(line) < 11 or len(line) % 2 != 1:
                    break

                # next two bytes are the byte count
                num_bytes = int.from_bytes(bytes.fromhex(line[1:3]), byteorder='big')

                record_type = int.from_bytes(bytes.fromhex(line[7:9]), byteorder='big')

                # record type 0 is data, record type 1 is end of data
                # Other record types do not include any actual data.
                if record_type == 1:
                    end_of_ihex = True
                    break
                if record_type == 0:
                    ihexdata = bytes.fromhex(line[9:9+num_bytes*2])
                    outfile.write(ihexdata)
            ihex_file.close()
            yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['ihex']
    metadata = {}
