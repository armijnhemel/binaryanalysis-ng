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
from kaitaistruct import ValidationNotEqualError
#from . import odex

from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_odex

#class OdexUnpackParser(UnpackParser):
class OdexUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'dey\n036\x00')
    ]
    pretty_name = 'odex'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_odex(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = odex.Odex.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = self.data.ofs_opt + self.data.len_opt

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        # write dex
        unpacked_files = []
        out_labels = []

        # cut .odex from the path name if it is there
        if self.fileresult.filename.suffix == '.odex':
            file_path = pathlib.Path(self.fileresult.filename.with_suffix('.dex').name)
        # else anonymous file
        else:
            file_path = pathlib.Path("unpacked_from_odex")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        outfile.write(self.data.raw_dex)
        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'odex']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
