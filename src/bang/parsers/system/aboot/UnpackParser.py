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

    labels = ['aboot', 'android']
    metadata = {}
