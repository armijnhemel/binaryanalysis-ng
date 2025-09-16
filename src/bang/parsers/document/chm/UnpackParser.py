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

import os
import pathlib
import shutil
import stat
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import chm


class ChmUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ITSF\x03\x00\x00\x00')
    ]
    pretty_name = 'chm'

    def parse(self):
        check_condition(shutil.which("7z") is not None, "7z not installed")
        try:
            self.data = chm.Chm.from_io(self.infile)
            # force parsing because Kaitai Struct evaluates lazily
            content = self.data.content
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        # run a test with 7z
        self.havetmpfile = False
        if not (self.offset == 0 and self.infile.size == self.data.filesize):
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            self.havetmpfile = True
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.data.filesize)
            os.fdopen(self.temporary_file[0]).close()

        if self.havetmpfile:
            p = subprocess.Popen(['7z', 't', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['7z', 't', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if p.returncode != 0:
            if self.havetmpfile:
                os.unlink(self.temporary_file[1])
            raise UnpackParserException("invalid CHM file according to 7z")

        # now actually unpack to rule out any more 7z errors
        self.unpack_directory = pathlib.Path(tempfile.mkdtemp(dir=self.configuration.temporary_directory))

        if self.havetmpfile:
            p = subprocess.Popen(['7z', f'-o{self.unpack_directory}', '-y', 'x', self.temporary_file[1]],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['7z', f'-o{self.unpack_directory}', '-y', 'x', self.infile.name],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if self.havetmpfile:
            os.unlink(self.temporary_file[1])

        if p.returncode != 0:
            raise UnpackParserException("invalid CHM file according to 7z")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.filesize

    def unpack(self, meta_directory):
        # walk the results directory
        for result in self.unpack_directory.glob('**/*'):
            # first change the permissions
            result.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            file_path = result.relative_to(self.unpack_directory)

            if result.is_symlink():
                meta_directory.unpack_symlink(file_path, result.readlink())
            elif result.is_dir():
                meta_directory.unpack_directory(file_path)
            elif result.is_file():
                with meta_directory.unpack_regular_file_no_open(file_path) as (unpacked_md, outfile):
                    self.local_copy2(result, outfile)
                    yield unpacked_md
            else:
                continue

        shutil.rmtree(self.unpack_directory)

    # a wrapper around shutil.copy2 to copy symbolic links instead of
    # following them and copying the data.
    def local_copy2(self, src, dest):
        '''Wrapper around shutil.copy2 for squashfs unpacking'''
        return shutil.copy2(src, dest, follow_symlinks=False)

    labels = ['chm', 'compressed', 'resource']
    metadata = {}
