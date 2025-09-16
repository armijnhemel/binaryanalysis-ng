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

import pathlib
import ssl

from bang.UnpackParser import UnpackParser
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

            # force read some data because of Kaitai's lazy evaluation
            certificate_chain = ssl.DER_cert_to_PEM_cert(self.data.image.certificate_chain)
        except (Exception, ValidationFailedError, ssl.SSLError) as e:
            raise UnpackParserException(e.args) from e

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
