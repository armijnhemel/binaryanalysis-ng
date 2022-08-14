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

from UnpackParser import WrappedUnpackParser
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import qcdt


class QcdtUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QCDT')
    ]
    pretty_name = 'qcdt'

    def parse(self):
        try:
            self.data = qcdt.Qcdt.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        offset_to_entry = {}
        ctr = 1
        for entry in self.data.device_entries:
            out_labels = []
            dtb_name = pathlib.Path("dtb-%d" % ctr)
            outfile_rel = self.rel_unpack_dir / dtb_name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            if entry.ofs_dtb not in offset_to_entry:
                outfile = open(outfile_full, 'wb')
                outfile.write(entry.data)
                outfile.close()
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                offset_to_entry[entry.ofs_dtb] = dtb_name
            else:
                outfile_full.symlink_to(offset_to_entry[entry.ofs_dtb])
                fr = FileResult(self.fileresult, outfile_rel, set(['symbolic link']))
            unpacked_files.append(fr)
            ctr += 1
        return unpacked_files

    def calculate_unpacked_size(self):
        self.unpacked_size = 0
        for entry in self.data.device_entries:
            self.unpacked_size = max(self.unpacked_size, entry.ofs_dtb + entry.len_dtb)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'qcdt']
        metadata = {}
        metadata['device'] = {}
        ctr = 1
        for entry in self.data.device_entries:
            metadata['device'][ctr] = {}
            metadata['device'][ctr]['platform_id'] = entry.platform_id.name
            metadata['device'][ctr]['variant_id'] = entry.variant_id
            metadata['device'][ctr]['soc_revision'] = entry.soc_revision
            if self.data.version > 1:
                metadata['device'][ctr]['subtype_id'] = entry.subtype_id
            if self.data.version > 2:
                metadata['device'][ctr]['pmic0'] = entry.pmic0
                metadata['device'][ctr]['pmic1'] = entry.pmic1
                metadata['device'][ctr]['pmic2'] = entry.pmic2
                metadata['device'][ctr]['pmic3'] = entry.pmic3
            ctr += 1

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
