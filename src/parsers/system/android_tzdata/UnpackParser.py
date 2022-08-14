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

from . import android_tzdata

class TzdataUnpackParser(UnpackParser):
    extensions = ['tzdata']
    signatures = []
    pretty_name = 'tzdata'

    def parse(self):
        self.unpacked_size = 0
        try:
            self.data = android_tzdata.AndroidTzdata.from_io(self.infile)

            # first some sanity checks, read the entries
            for entry in self.data.index.entries:
                # compute the unpacked size. Use len(entry.raw_tzif) to force
                # the parser to actually read the data
                self.unpacked_size = max(self.unpacked_size, self.data.ofs_data + entry.ofs_timezone + len(entry.raw_tzif))

            # read the zone tab info
            for entry in self.data.zonetab.entries:
                pass

            self.unpacked_size = max(self.unpacked_size, self.data.ofs_zonetab + len(self.data._raw__m_zonetab))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        unpacked_files = []

        for entry in self.data.index.entries:
            outfile_rel = self.rel_unpack_dir / entry.zonename
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(entry.raw_tzif)
            outfile.close()
            fr = FileResult(self.fileresult, self.rel_unpack_dir / entry.zonename, set(['tzif', 'resource']))
            unpacked_files.append(fr)

        outfile_rel = self.rel_unpack_dir / 'zone.tab'
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.data._raw__m_zonetab)
        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / 'zone.tab', set())
        unpacked_files.append(fr)
        return unpacked_files


    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'resource', 'timezone', 'android' ]
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
