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

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import tplink_tx6610v4
from . import tplink


class TplinkkUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (4, b'TP-LINK Technologies')
    ]
    pretty_name = 'tplink'

    def parse(self):
        try:
            self.data = tplink.Tplink.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.header.len_image

    def unpack(self, meta_directory):
        # first the kernel
        file_path = pathlib.Path('kernel')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.kernel)
            yield unpacked_md

        file_path = pathlib.Path('rootfs')

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.rootfs)
            yield unpacked_md

    labels = ['tplink', 'firmware']

    @property
    def metadata(self):
        metadata = {}
        return metadata


class TplinkTx6610v4kUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'2RDH')
    ]
    pretty_name = 'tplink_tx6610v4'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = tplink_tx6610v4.TplinkTx6610v4.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        # first the kernel
        if self.data.header.rest_of_header.len_kernel != 0:
            file_path = pathlib.Path('kernel')

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.kernel)
                yield unpacked_md
        if self.data.header.rest_of_header.len_rootfs != 0:
            file_path = pathlib.Path('rootfs')

            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(self.data.rootfs)
                yield unpacked_md

    labels = ['tplink_tx6610v4', 'firmware']

    @property
    def metadata(self):
        metadata = {}
        metadata['name'] = self.data.header.rest_of_header.name
        return metadata
