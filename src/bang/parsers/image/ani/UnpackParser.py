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

'''
Parser for ANI files. The parser here is correct, but there are a lot
of ANI files where the length declared in the file is 8 bytes less than
supposed. These files are not correctly recognized.

test files for ANI: http://www.anicursor.com/diercur.html
http://fileformats.archiveteam.org/wiki/Windows_Animated_Cursor#Sample_files
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import ani


class AniUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'ACON')
    ]
    pretty_name = 'ani'

    def parse(self):
        try:
            self.data = ani.Ani.from_io(self.infile)
            # force reading of data because of Kaitai's lazy evaluation
            for c in self.data.subchunks:
                chunk_id = c.chunk.id
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    labels = ['ani', 'graphics']
    metadata = {}
