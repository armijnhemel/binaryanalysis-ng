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
Parse and unpack GNU message catalog files.

The on disk format for GNU message catalog files is described here:
https://www.gnu.org/software/gettext/manual/gettext.html#index-file-format_002c-_002emo
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError, UndecidedEndiannessError
from . import gettext_mo


class GnuMessageCatalogUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xde\x12\x04\x95'),
        (0, b'\x95\x04\x12\xde')
    ]
    pretty_name = 'gnu_message_catalog'

    def parse(self):
        file_size = self.infile.size
        try:
            self.data = gettext_mo.GettextMo.from_io(self.infile)
            # this is a bit of an ugly hack as the Kaitai parser is
            # not entirely complete. Use this to detect if the file
            # has been truncated.
            check_condition(self.data.mo.ofs_originals <= file_size,
                            "invalid offset")
            check_condition(self.data.mo.ofs_translations <= file_size,
                            "invalid offset")
            check_condition(self.data.mo.ofs_hashtable_items <= file_size,
                            "invalid offset")
            for i in self.data.mo.originals:
                a = type(i.str)
            for i in self.data.mo.translations:
                a = type(i.str)
            # it could be that the file has been truncated and
            # that the last NUL is missing. TODO.
        except (Exception, ValidationFailedError, UndecidedEndiannessError) as e:
            raise UnpackParserException(e.args) from e

        check_condition(self.data.mo.version.major in [0,1],
                        "unknown GNU message catalog version number")

    def calculate_unpacked_size(self):
        self.unpacked_size = max(self.data.mo.ofs_originals,
                                 self.data.mo.ofs_translations,
                                 self.data.mo.ofs_hashtable_items)
        # compute the size. Note: these strings are NUL-terminated, but
        # the NUL is not included in the length of the string.
        for i in self.data.mo.originals:
            self.unpacked_size = max(self.unpacked_size, i.ofs_str + i.len_str + 1)
        for i in self.data.mo.translations:
            self.unpacked_size = max(self.unpacked_size, i.ofs_str + i.len_str + 1)

    labels = [ 'resource', 'GNU message catalog']
    metadata = {}
