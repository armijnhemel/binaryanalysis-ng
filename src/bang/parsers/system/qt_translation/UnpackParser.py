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
from . import qt_translation


class QtTranslationUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3c\xb8\x64\x18\xca\xef\x9c\x95\xcd\x21\x1c\xbf\x60\xa1\xbd\xdd')
    ]
    pretty_name = 'qt_translation'

    def parse(self):
        try:
            self.data = qt_translation.QtTranslation.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        for t in self.data.tags:
            if t.tag == qt_translation.QtTranslation.TranslatorTags.messages:
                for m in t.data.messages:
                    if m.tag == qt_translation.QtTranslation.TagTypes.translation:
                        try:
                            m.payload.data.decode('utf-16be')
                        except UnicodeDecodeError as e:
                            raise UnpackParserException(e.args) from e

    labels = ['qt', 'translation', 'resource']
    metadata = {}
