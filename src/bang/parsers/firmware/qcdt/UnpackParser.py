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

import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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

    def unpack(self, meta_directory):
        offset_to_entry = {}
        ctr = 1
        for entry in self.data.device_entries:
            dtb_name = pathlib.Path("dtb-%d" % ctr)
            if entry.ofs_dtb not in offset_to_entry:
                with meta_directory.unpack_regular_file(dtb_name) as (unpacked_md, outfile):
                    outfile.write(entry.data)
                    yield unpacked_md
                offset_to_entry[entry.ofs_dtb] = dtb_name
            else:
                meta_directory.unpack_symlink(dtb_name, offset_to_entry[entry.ofs_dtb])
                # unpack symlink does not get a meta directory
            ctr += 1

    def calculate_unpacked_size(self):
        self.unpacked_size = 0
        for entry in self.data.device_entries:
            self.unpacked_size = max(self.unpacked_size, entry.ofs_dtb + entry.len_dtb)

    labels = ['android', 'qcdt']

    @property
    def metadata(self):
        metadata = {}
        metadata['device'] = {}
        ctr = 1
        for entry in self.data.device_entries:
            metadata['device'][ctr] = {
                'variant_id': entry.variant_id,
                'soc_revision': entry.soc_revision
            }

            if type(entry.platform_id) == int:
                metadata['device'][ctr]['platform_id']: entry.platform_id
            else:
                metadata['device'][ctr]['platform_id']: entry.platform_id.name

            if self.data.version > 1:
                metadata['device'][ctr] = {}
                metadata['device'][ctr]['subtype_id'] = entry.subtype_id
            if self.data.version > 2:
                metadata['device'][ctr]['pmic0'] = entry.pmic0
                metadata['device'][ctr]['pmic1'] = entry.pmic1
                metadata['device'][ctr]['pmic2'] = entry.pmic2
                metadata['device'][ctr]['pmic3'] = entry.pmic3
            ctr += 1
        return metadata
