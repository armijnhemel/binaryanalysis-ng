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

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import terminfo
from . import terminfo_extended


class TerminfoUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1a\x01')
    ]
    pretty_name = 'terminfo'

    def parse(self):
        try:
            self.data = terminfo_extended.TerminfoExtended.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            self.infile.infile.seek(self.infile.offset)
            try:
                self.data = terminfo.Terminfo.from_io(self.infile)
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)

        # sanity checks for the names
        check_condition(len(self.data.names_section.names) > 0,
                        "no name found")
        check_condition(self.data.names_section.names.isprintable(),
                        "invalid names section")
        check_condition(re.match(r'[a-zA-Z0-9][a-zA-Z0-9.][^|]*', self.data.names_section.names) is not None,
                        "invalid terminal name")

        for string_offset in self.data.strings_section.string_offset:
            if string_offset == 0xffff or string_offset == 0xfffe:
                continue
            check_condition(string_offset <= self.data.len_string_table,
                            "invalid offset into string table")

    labels = ['resource', 'terminfo']
    metadata = {}
