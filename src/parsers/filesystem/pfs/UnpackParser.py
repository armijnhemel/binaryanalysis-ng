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

# https://web.archive.org/web/20120511095357/https://0entropy.blogspot.com/2011/08/firmware-reverse-engineering.html
# Test firmware (40 bytes file entry): https://www.touslesdrivers.com/index.php?v_page=23&v_code=15240&v_langue=en

import os
import pathlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import pfs
from . import pfs_40


class PfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PFS/0.9\x00')
    ]
    pretty_name = 'pfs'

    def parse(self):
        try:
            self.data = pfs.Pfs.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            self.infile.infile.seek(self.infile.offset)
            try:
                self.data = pfs_40.Pfs40.from_io(self.infile)
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)

        self.unpacked_size = self.infile.tell()
        try:
            # walk the entries to see if they have data
            for entry in self.data.files:
                self.unpacked_size = max(self.unpacked_size, entry.pos + len(entry.data))
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        unpacked_files = []

        for entry in self.data.files:
            out_labels = []

            file_path = pathlib.PureWindowsPath(entry.name)
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(entry.data)
            outfile.close()
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files


    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['pfs', 'filesystem']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
