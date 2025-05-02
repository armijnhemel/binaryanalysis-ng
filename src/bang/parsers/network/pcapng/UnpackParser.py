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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import pcapng


class PcapngUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x0a\x0d\x0d\x0a')
    ]
    pretty_name = 'pcapng'

    def parse(self):
        try:
            self.data = pcapng.Pcapng.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        section_header_seen = False
        for block in self.data.blocks:
            if block.header_type == pcapng.Pcapng.HeaderTypes.section_header:
                section_header_seen = True
                break
        check_condition(section_header_seen, "no section header block found")

    labels = ['pcapng']
    metadata = {}
