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
from kaitaistruct import ValidationNotEqualError
from . import qcdt
from bangunpack import unpack_qcdt


class QcdtUnpackParser(WrappedUnpackParser):
#class QcdtUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QCDT')
    ]
    pretty_name = 'qcdt'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_qcdt(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = qcdt.Qcdt.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
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
        #metadata['hardware'] = {}
        #metadata['hardware']['usb_product_id'] = self.data.img_header.usb_pid
        #metadata['hardware']['usb_vendor_id'] = self.data.img_header.usb_vid
        #metadata['hardware']['hardware_id'] = self.data.img_header.hardware_id
        #metadata['hardware']['firmware_id'] = self.data.img_header.firmware_id

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
