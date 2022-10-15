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
import ssl

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import aboot


class AbootUnpackParser(UnpackParser):
    extensions = ['aboot']
    signatures = []
    pretty_name = 'aboot'

    def parse(self):
        try:
            self.data = aboot.Aboot.from_io(self.infile)
            certificate_chain = ssl.DER_cert_to_PEM_cert(self.data.image.certificate_chain)
        except (Exception, ValidationFailedError, ssl.SSLError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        file_path = pathlib.Path("image")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.image.raw_appsbl)
            yield unpacked_md

        file_path = pathlib.Path("signature")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.image.signature)
            yield unpacked_md

        file_path = pathlib.Path("certificate_chain")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.image.certificate_chain)
            yield unpacked_md


    labels = ['aboot', 'android']
    metadata = {}
