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
from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError, ValidationNotAnyOfError
from . import glibc_utmp

class UtmpUnpackParser(UnpackParser):
    extensions = ['utmp', 'wtmp']
    signatures = []
    pretty_name = 'utmp'

    def parse(self):
        try:
            self.data = glibc_utmp.GlibcUtmp.from_io(self.infile)
        except (Exception, ValidationNotEqualError, ValidationNotAnyOfError) as e:
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['utmp']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)