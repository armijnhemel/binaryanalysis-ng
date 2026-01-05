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

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import btf, btf_ext


class BtfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x9f\xeb')
    ]
    pretty_name = 'btf'

    def parse(self):
        try:
            self.data = btf.Btf.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    labels = ['btf']

    @property
    def metadata(self):
        metadata = {}
        metadata['strings'] = self.data.string_section.strings
        return metadata


class BtfExtUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x9f\xeb')
    ]
    pretty_name = 'btf_ext'

    def parse(self):
        try:
            self.data = btf_ext.BtfExt.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    labels = ['btf_ext']
    metadata = {}
