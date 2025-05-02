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
from . import cab


class CabUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MSCF\x00\x00\x00\x00')
    ]
    pretty_name = 'cab'

    def parse(self):
        if shutil.which('cabextract') is None:
            raise UnpackParserException("cabextract not installed")
        try:
            self.data = cab.Cab.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # test unpack to see if there are any cabextract errors.
        # First check if the file starts at offset 0. If not, carve
        # the file, as cabextract tries to be smart and unpack
        # all cab data in a file, like concatenated cab files,
        # even if there is other data in between the individual
        # cab files
        self.unpack_directory = pathlib.Path(tempfile.mkdtemp(dir=self.configuration.temporary_directory))

        havetmpfile = False
        if not (self.offset == 0 and self.infile.size == self.data.preheader.len_cabinet):
            temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            havetmpfile = True
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.data.preheader.len_cabinet)
            os.fdopen(temporary_file[0]).close()
            p = subprocess.Popen(['cabextract', '-d', self.unpack_directory, temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['cabextract', '-d', self.unpack_directory, self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if havetmpfile:
            os.unlink(temporary_file[1])

        if p.returncode != 0:
            shutil.rmtree(self.unpack_directory)
            raise UnpackParserException("Cannot unpack cab")

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

    labels = ['cab', 'archive']
    metadata = {}
