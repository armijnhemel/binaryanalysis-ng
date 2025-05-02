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

# QCOW2 is a file format used by QEMU. It can be inspected and converted
# using the qemu-img tool, but tool isn't completely accurate: the
# "actual size" that is reported often isn't accurate (too large), making
# carving difficult. For most practical purposes it is probably good
# enough to look at the entire file.

import json
import os
import pathlib
import shutil
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import qcow2


class Qcow2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QFI\xfb')
    ]
    pretty_name = 'qcow2'

    def parse(self):
        check_condition(shutil.which('qemu-img') is not None,
                        "qemu-img program not found")
        check_condition(self.offset == 0, "carving not supported")
        try:
            self.data = qcow2.Qcow2.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # run qemu-img to see if the whole file is the qcow2 file
        # Carving unfortunately doesn't seem to work well.
        p = subprocess.Popen(['qemu-img', 'info', '--output=json', self.infile.name],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()
        check_condition(p.returncode == 0, "not a valid qcow2 file or cannot unpack")

        try:
            vmdkjson = json.loads(standardout)
        except:
            raise UnpackParserException("no valid JSON output from qemu-img")

        # convert the file to a temporary file to rule out any unpacking errors
        self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
        os.fdopen(self.temporary_file[0]).close()
        p = subprocess.Popen(['qemu-img', 'convert', '-O', 'raw', self.infile.name, self.temporary_file[1]],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (standardout, standarderror) = p.communicate()

        if p.returncode != 0:
            os.unlink(self.temporary_file[1])
        check_condition(p.returncode == 0, "not a valid qcow2 file or cannot unpack")
        self.unpacked_size = min(vmdkjson['actual-size'], self.infile.size)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        unpacked_files = []

        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() in ['.qcow2', '.qcow', '.qcow2c', '.img']:
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_qcow2")
        else:
            file_path = pathlib.Path("unpacked_from_qcow2")

        with meta_directory.unpack_regular_file_no_open(file_path) as (unpacked_md, outfile):
            shutil.copy(self.temporary_file[1], outfile)
            os.unlink(self.temporary_file[1])
            yield unpacked_md

    labels = ['qemu', 'qcow2', 'filesystem']
    metadata = {}
