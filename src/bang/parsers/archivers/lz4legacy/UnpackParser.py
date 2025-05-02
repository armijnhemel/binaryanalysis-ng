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

# Test files can be created with 'lz4c -l'

import os
import pathlib
import shutil
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import lz4_legacy
from . import lz4_legacy_kernel


class Lz4legacyUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x02\x21\x4c\x18')
    ]
    pretty_name = 'lz4_legacy'

    def __init__(self, from_meta_directory, offset, configuration):
        super().__init__(from_meta_directory, offset, configuration)
        self.from_md = from_meta_directory

    def parse(self):
        if shutil.which('lz4c') is None:
            raise UnpackParserException("lz4c not installed")
        try:
            self.data = lz4_legacy.Lz4Legacy.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            propagated = self.from_md.info.get('propagated', {})

            if 'parent_parser' in propagated:
                if propagated['parent_parser'] == 'linux_x86':
                    try:
                        self.infile.seek(0)
                        self.data = lz4_legacy_kernel.Lz4LegacyKernel.from_io(self.infile)
                    except (Exception, ValidationFailedError) as e:
                        raise UnpackParserException(e.args)
                else:
                    raise UnpackParserException(e.args)
            else:
                raise UnpackParserException(e.args)

        # correctly set unpacked_size
        self.unpacked_size = 4
        for block in self.data.blocks:
            if not block.is_magic:
                self.unpacked_size += 4 + block.len_data

        # check if the file starts at offset 0 and if the file length
        # equals the entire file. If not, carve the file first, as multiple
        # streams can be concatenated and lz4c will concatenate results
        self.havetmpfile = False
        if not (self.offset == 0 and self.infile.size == self.unpacked_size):
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            self.havetmpfile = True
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(self.temporary_file[0]).close()

        if self.havetmpfile:
            p = subprocess.Popen(['lz4c', '-cd', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['lz4c', '-cd', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if p.returncode != 0:
            if self.havetmpfile:
                os.unlink(self.temporary_file[1])
            raise UnpackParserException("Cannot decompress lz4 data")

    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        # unpack the data using lz4c. Currently the python-lz4 package
        # does not support the legacy format, see
        # https://github.com/python-lz4/python-lz4/issues/169

        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.lz4':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_lz4legacy")
        else:
            file_path = pathlib.Path("unpacked_from_lz4legacy")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            if self.havetmpfile:
                p = subprocess.Popen(['lz4c', '-d', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)
            else:
                p = subprocess.Popen(['lz4c', '-cd', self.infile.name], stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()

            if self.havetmpfile:
                os.unlink(self.temporary_file[1])
            yield unpacked_md

    labels = ['compressed', 'lz4']
    metadata = {}
