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

'''
Parse and unpack Chrome PAK files

These files contain various resources (such as PNGs), and
localized strings and are frequently used on Android.

version 4:
http://dev.chromium.org/developers/design-documents/linuxresourcesandlocalizedstrings
https://chromium.googlesource.com/chromium/src/tools/grit/+/22f7a68bb5ad68fe4192d0f34466049038735b9c/grit/format/data_pack.py

version 5:
https://chromium.googlesource.com/chromium/src/tools/grit/+/master/grit/format/data_pack.py
'''

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import chrome_pak


class ChromePakUnpackParser(UnpackParser):
    extensions = ['.pak']
    signatures = []
    pretty_name = 'pak'

    def parse(self):
        resource_ids = set()
        try:
            self.data = chrome_pak.ChromePak.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.resources[-1].id == 0, "wrong resource identifier")
        check_condition(self.data.resources[-1].ofs_body <= self.infile.size,
                        "not enough data")

    def unpack(self, meta_directory):
        resources = self.data.resources
        for i in range(0, len(resources)-1):
            file_path = pathlib.Path("resource-%d" % resources[i].id)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(resources[i].body)

                # pass some information to the unpacked files about
                # the parent to avoid the base64 unpacker from running
                with unpacked_md.open(open_file=False):
                    unpacked_md.info['parent'] = "chrome pak"
                yield unpacked_md

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.resources[-1].ofs_body

    labels = ['pak', 'resource']

    @property
    def metadata(self):
        return { 'version' : self.data.version }
