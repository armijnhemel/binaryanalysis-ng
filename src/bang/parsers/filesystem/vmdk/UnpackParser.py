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

import json
import math
import os
import pathlib
import shutil
import subprocess

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import vmware_vmdk


class VmdkUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'KDMV')
    ]
    pretty_name = 'vmdk'

    def parse(self):
        if shutil.which('qemu-img') is None:
            raise UnpackParserException("qemu-img not installed")
        try:
            self.data = vmware_vmdk.VmwareVmdk.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(pow(2, int(math.log2(self.data.header.size_grain,))) == self.data.header.size_grain,
                        "invalid grain size")
        check_condition(self.data.header.size_max % self.data.header.size_grain == 0,
                        "invalid capacity")

        check_condition(self.data.header.size_metadata * self.data.len_sector <= self.infile.size,
                        "invalid meta data size")

        # run a sanity check using qemu-img
        check_condition(self.infile.offset == 0, "vmdk carving not supported")
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', self.infile.name],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            try:
                vmdkjson = json.loads(standardout)
            except:
                raise UnpackParserException('no valid JSON output from qemu-img')
        else:
            raise UnpackParserException('invalid VMDK')
        check_condition(self.infile.size == vmdkjson['actual-size'],
                        "invalid size")
        self.unpacked_size = vmdkjson['actual-size']

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        unpacked_files = []

        if meta_directory.file_path.suffix.lower() == '.vmdk':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_vmdk")
        else:
            file_path = pathlib.Path("unpacked_from_vmdk")

        with meta_directory.unpack_regular_file_no_open(file_path) as (unpacked_md, outfile):
            # now convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', self.infile.name, outfile],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)

            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                raise UnpackParserException('cannot convert vmdk file')
            yield unpacked_md

    labels = ['vmdk', 'filesystem']
    metadata = {}
