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
import pathlib
import shutil
import subprocess

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import vdi


class VdiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'<<< Oracle VM VirtualBox Disk Image >>>\n'),
        (0, b'<<< QEMU VM Virtual Disk Image >>>\n')
    ]
    pretty_name = 'vdi'

    def parse(self):
        if shutil.which('qemu-img') is None:
            raise UnpackParserException("qemu-img not installed")
        try:
            self.data = vdi.Vdi.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        vdi_size = self.data.header.block_size * (self.data.header.header_main.blocks_allocated + 2)
        check_condition(vdi_size <= self.infile.size, "not enough data for vdi")

        # run a sanity check using qemu-img
        check_condition(self.infile.offset == 0 and vdi_size == self.infile.size,
                        "vdi carving not supported")
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', self.infile.name],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        (standardout, standarderror) = p.communicate()
        if p.returncode == 0:
            try:
                vdijson = json.loads(standardout)
            except:
                raise UnpackParserException('no valid JSON output from qemu-img')
        self.unpacked_size = vdi_size

        # TODO: test unpack here

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        if meta_directory.file_path.suffix.lower() == '.vdi':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_vdi")
        else:
            file_path = pathlib.Path("unpacked_from_vdi")

        with meta_directory.unpack_regular_file_no_open(file_path) as (unpacked_md, outfile):
            # convert it to a raw file
            p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', self.infile.name, outfile],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)

            (standardout, standarderror) = p.communicate()
            if p.returncode != 0:
                raise UnpackParserException('cannot convert vdi file')
            yield unpacked_md

    labels = ['virtualbox', 'vdi', 'filesystem']
    metadata = {}
