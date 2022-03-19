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
import pathlib
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['locale', 'resource']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
