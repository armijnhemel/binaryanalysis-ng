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

import base64
import binascii
import pathlib
import sys

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


KNOWN_DIRECTORIES = [b'/bin/', b'/etc/', b'/usr/', b'/lib/']

class Base64UnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'base64'

    def __init__(self, from_meta_directory, offset, configuration):
        super().__init__(from_meta_directory, offset, configuration)
        self.from_md = from_meta_directory

    def parse(self):
        # check if the file is from a Chrome PAK file. This is
        # to avoid lots of unnecessary scanning.
        parent = self.from_md.info.get('parent', [])
        check_condition('chrome pak' not in parent,
                        'parent file Chrome PAK')

        # add a cut off value to prevent many false positives
        base64cutoff = 8
        check_condition(self.infile.size >= base64cutoff, 'file too small')

        unpacked = 0

        line_counter = 0

        # open the file again, but in text mode
        try:
            base64_file = open(self.infile.name, 'r')

            len_previous_line = sys.maxsize
            # first check to see if the file has consistent
            # line wrapping and if there are any characters
            # that are not in any known base16/32/64 alphabets
            for line in base64_file:
                base64_line = line.strip()
                if " " in base64_line:
                    break
                if len(base64_line) != '':
                    pass
                if len(base64_line) > len_previous_line:
                    break
                len_previous_line = len(base64_line)
                try:
                    unpacked += len(base64_line) + len(base64_file.newlines)
                except:
                    unpacked += len(base64_line)
                line_counter += 1
        except UnicodeDecodeError as e:
            raise UnpackParserException(e.args)
        finally:
            base64_file.close()

        check_condition(line_counter >= 1, "no base64 bytes in file")

        # now read 'unpacked' bytes for more sanity checks and
        # finding out which decoder is used.
        base64_bytes = self.infile.read(unpacked)

        # Known Unix file paths are a big source of false positives.
        for d in KNOWN_DIRECTORIES:
            if base64_bytes.startswith(d):
                check_condition(False, "file path, no base64")

        # first remove all the different line endings. These are not
        # valid characters in the base64 alphabet, plus it also conveniently
        # translates CRLF encoded files.
        base64_bytes = base64_bytes.replace(b'\n', b'')
        base64_bytes = base64_bytes.replace(b'\r', b'')

        if line_counter == 1:
            # a few sanity checks: there are frequently false positives
            # for MD5, SHA1, SHA256, etc.
            if len(base64_bytes) in [32, 40, 64]:
                raise UnpackParserException("likely MD5/SHA1/SHA256, not base64")

        decoded = False

        # first base16
        try:
            self.decoded_data = base64.b16decode(base64_bytes)
            decoded = True
            self.encoding = ['base16']
        except binascii.Error:
            pass

        # base32
        if not decoded:
            try:
                self.decoded_data = base64.b32decode(base64_bytes)
                decoded = True
                self.encoding = ['base32']
            except binascii.Error:
                pass

        # base32, mapping
        if not decoded:
            try:
                self.decoded_data = base64.b32decode(base64_bytes, map01='I')
                decoded = True
                self.encoding = ['base32']
            except binascii.Error:
                pass

        # base32, mapping
        if not decoded:
            try:
                self.decoded_data = base64.b32decode(base64_bytes, map01='L')
                decoded = True
                self.encoding = ['base32']
            except binascii.Error:
                pass

        # regular base64
        if not decoded:
            invalidbase64 = False
            validbase64chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r')
            # check if the characters are in the base64 index table
            for i in base64_bytes:
                if chr(i) not in validbase64chars:
                    invalidbase64 = True
                    break
            if not invalidbase64:
                try:
                    self.decoded_data = base64.standard_b64decode(base64_bytes)
                    if self.decoded_data != b'':
                        # sanity check: in an ideal situation the base64 data is
                        # 1/3 larger than the decoded data.
                        # Anything 1.5 times larger (or more) is bogus.
                        # TODO: is this necessary? the decoder will not result in
                        # output larger than possible
                        if len(base64_bytes)/len(self.decoded_data) < 1.5:
                            decoded = True
                            self.encoding = ['base64']
                except binascii.Error:
                    pass

        # URL safe base64 (RFC 4648, section 5)
        if not decoded:
            invalidbase64 = False
            validbase64chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=\n\r')
            # check if the characters are in the base64 index table
            for i in base64_bytes:
                if chr(i) not in validbase64chars:
                    invalidbase64 = True
                    break
            if not invalidbase64:
                try:
                    self.decoded_data = base64.urlsafe_b64decode(base64_bytes)
                    if self.decoded_data != b'':
                        # sanity check: in an ideal situation the base64 data is
                        # 1/3 larger than the decoded data.
                        # Anything 1.5 times larger (or more) is bogus.
                        # TODO: is this necessary? the decoder will not result in
                        # output larger than possible
                        if len(base64_bytes)/len(self.decoded_data) < 1.5:
                            decoded = True
                            self.encoding = ['base64', 'urlsafe']
                except binascii.Error:
                    pass

        check_condition(decoded and self.decoded_data != b'', "no base64")

    def unpack(self, meta_directory):
        unpacked_files = []
        out_labels = []

        if meta_directory.file_path.suffix.lower() in ['.base64', '.b64']:
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_base64")
        else:
            file_path = pathlib.Path("unpacked_from_base64")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.decoded_data)
            yield unpacked_md

    @property
    def labels(self):
        labels = self.encoding
        return labels

    metadata = {}
