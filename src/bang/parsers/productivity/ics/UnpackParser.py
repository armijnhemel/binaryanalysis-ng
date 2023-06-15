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

# https://www.ietf.org/rfc/rfc5545.txt

import icalendar

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class IcsUnpackParser(UnpackParser):
    extensions = ['.ics']
    signatures = [
    ]
    pretty_name = 'ics'

    def parse(self):
        # open the file again, but then in text mode
        try:
            with open(self.infile.name, 'r') as ics_file:
                icalendar.Calendar.from_ical(ics_file.read())
        except Exception as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.size

    labels = ['ics', 'resource']
    metadata = {}
