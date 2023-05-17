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

# https://en.wikipedia.org/wiki/Intel_HEX
# It is assumed that only files that are completely text
# files can be IHex files.

import base64
import json
import pathlib
import zlib

import defusedxml

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class Px4UnpackParser(UnpackParser):
    extensions = ['.px4']
    signatures = [
    ]
    pretty_name = 'px4'

    def parse(self):
        try:
            self.data = json.load(self.infile)
        except (json.JSONDecodeError, UnicodeError) as e:
            raise UnpackParserException("cannot decode PX4 JSON")

        check_condition('image' in self.data, "firmware image data not found")
        check_condition('parameter_xml' in self.data, "parameter.xml data not found")
        check_condition('airframe_xml' in self.data, "airframe.xml data not found")

        # then try to decode the base64 encoded data
        self.image_data = base64.b64decode(self.data['image'])

        try:
            self.image = zlib.decompress(base64.b64decode(self.data['image']))
        except Exception as e:
            raise UnpackParserException(e.args)

        try:
            self.parameter_xml = zlib.decompress(base64.b64decode(self.data['parameter_xml']))
            defusedxml.minidom.parseString(self.parameter_xml)
        except Exception as e:
            raise UnpackParserException(e.args)

        try:
            self.airframe_xml = zlib.decompress(base64.b64decode(self.data['airframe_xml']))
            defusedxml.minidom.parseString(self.airframe_xml)
        except Exception as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        file_path = pathlib.Path('image')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.image)
            yield unpacked_md

        file_path = pathlib.Path('parameter.xml')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.parameter_xml)
            yield unpacked_md

        file_path = pathlib.Path('airframe.xml')
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.airframe_xml)
            yield unpacked_md

    labels = ['px4']

    @property
    def metadata(self):
        metadata = {}
        if 'description' in self.data:
            metadata['description'] = self.data['description']
        if 'version' in self.data:
            metadata['version'] = self.data['version']
        if 'git_hash' in self.data:
            metadata['git_hash'] = self.data['git_hash']
        if 'git_identity' in self.data:
            metadata['git_identity'] = self.data['git_identity']
        if 'board_id' in self.data:
            metadata['board_id'] = self.data['board_id']
        return metadata
