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
from . import pcap


class PcapUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xd4\xc3\xb2\xa1'),
        (0, b'\xa1\xb2\xc3\xd4'),
        (0, b'\x4d\x3c\xb2\xa1'),
        (0, b'\xa1\xb2\x3c\x4d')
    ]
    pretty_name = 'pcap'

    def parse(self):
        try:
            self.data = pcap.Pcap.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    labels = ['pcap']

    @property
    def metadata(self):
        metadata = {}
        metadata['count'] = len(self.data.capture.packets)
        return metadata
