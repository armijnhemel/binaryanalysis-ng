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
from . import dfu


class DfuUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DfuSe')
    ]
    pretty_name = 'dfu'

    def parse(self):
        try:
            self.data = dfu.Dfu.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        target_counter = 1
        for target in self.data.targets:
            out_labels = []
            if target.name == '':
                target_name = pathlib.Path("unpacked-from-dfu-%d" % target_counter)
            else:
                target_name = pathlib.Path(target.name)

            outfile_rel = self.rel_unpack_dir / target_name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            for elem in target.elements:
                outfile.write(elem.data)
            outfile.close()

            fr = FileResult(self.fileresult, self.rel_unpack_dir / target_name, set(out_labels))
            unpacked_files.append(fr)
            target_counter += 1
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    #def calculate_unpacked_size(self):
        #pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['dfu', 'firmware']
        metadata = {}
        metadata['hardare'] = {}
        metadata['hardare']['product_id'] = self.data.product
        metadata['hardare']['vendor_id'] = self.data.vendor

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
