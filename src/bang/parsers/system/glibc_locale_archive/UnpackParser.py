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
from . import glibc_locale_archive


class GlibcLocaleArchiveUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x09\x01\x02\xde')
    ]
    pretty_name = 'glibc_locale_archive'

    def parse(self):
        try:
            self.data = glibc_locale_archive.GlibcLocaleArchive.from_io(self.infile)

            self.unpacked_size = max(self.data.ofs_string + self.data.len_string_table,
                                     self.data.ofs_namehash + self.data.len_name_hash_table,
                                     self.data.ofs_locrec_table + self.data.len_locrec_table)
            for entry in self.data.name_hash_table.entries:
                if entry.hash_value == 0:
                    continue
                for locrec in entry.locrec.loc_recs:
                    self.unpacked_size = max(self.unpacked_size, locrec.ofs_locrec + locrec.len_locrec)

                    # force evaluation check of locrec type
                    loc_rec_type = locrec.loc_rec_type
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['locale', 'resource']
    metadata = {}
