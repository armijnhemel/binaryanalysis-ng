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


import json
import math
import os
import pathlib
import shutil
import subprocess

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

        check_condition(self.data.header.size_metadata * self.data.len_sector <= self.fileresult.filesize,
                        "invalid meta data size")

        # run a sanity check using qemu-img
        check_condition(self.infile.offset == 0, "vmdk carving not supported")
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', self.fileresult.filename],
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
        check_condition(self.fileresult.filesize == vmdkjson['actual-size'],
                        "invalid size")
        self.unpacked_size = vmdkjson['actual-size']

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        unpacked_files = []

        if self.fileresult.filename.suffix.lower() == '.vmdk':
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_vmdk")
        else:
            file_path = pathlib.Path("unpacked_from_vmdk")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)

        # now convert it to a raw file
        p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', self.fileresult.filename, outfile_full],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

        (standardout, standarderror) = p.communicate()
        if p.returncode != 0:
            raise UnpackParserException('cannot convert vmdk file')

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
        unpacked_files.append(fr)

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['vmdk', 'filesystem']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
