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

import binascii
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import sevenzip


# https://en.wikipedia.org/wiki/7z
# Inside the 7z distribution there is a file called
#
# DOC/7zFormat.txt
#
# that describes the file format.
#
# This unpacker can recognize 7z formats, but only if the 7z file
# consists of a single frame.
#
# Variants exist: Texas Instruments' AR7 uses a modified
# version with that identifies itself as version 48.50
# which cannot be unpacked with an unmodified 7z
class SevenzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'7z\xbc\xaf\x27\x1c')
    ]
    pretty_name = '7z'

    def parse(self):
        check_condition(shutil.which('7z') is not None, '7z program not found')
        try:
            self.data = sevenzip.Sevenzip.from_io(self.infile)
            computed_crc = binascii.crc32(self.data.header.start_header.next_header)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        check_condition(self.data.header.start_header.next_header_crc == computed_crc,
                        "invalid next header CRC")

        computed_crc = binascii.crc32(self.data.header._raw_start_header)
        check_condition(self.data.header.start_header_crc == computed_crc,
                        "invalid start header CRC")

        self.encrypted = False

        # header is 32 bytes
        self.unpacked_size = 32

        # then add the next header offset and length
        self.unpacked_size += self.data.header.start_header.ofs_next_header
        self.unpacked_size += self.data.header.start_header.len_next_header

        # check if the file starts at offset 0. If not, carve the
        # file first, as 7z tries to be smart and look at
        # all data in a file
        self.havetmpfile = False
        if not (self.offset == 0 and self.infile.size == self.unpacked_size):
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            self.havetmpfile = True
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(self.temporary_file[0]).close()

        if self.havetmpfile:
            p = subprocess.Popen(['7z', 'l', '-y', '-p', '', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['7z', 'l', '-y', '-p', '', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if p.returncode != 0:
            if self.havetmpfile:
                os.unlink(self.temporary_file[1])
            if p.returncode == 2:
                if b'password' in errormsg:
                    self.encrypted = True
                else:
                    raise UnpackParserException("Cannot unpack 7z")
            else:
                raise UnpackParserException("Cannot unpack 7z")
        else:
            # do an actual test unpack
            self.unpack_directory = pathlib.Path(tempfile.mkdtemp(dir=self.configuration.temporary_directory))

            if self.havetmpfile:
                p = subprocess.Popen(['7z', f'-o{self.unpack_directory}', '-y', 'x', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                p = subprocess.Popen(['7z', f'-o{self.unpack_directory}', '-y', 'x', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()

            if self.havetmpfile:
                os.unlink(self.temporary_file[1])

            if p.returncode != 0:
                shutil.rmtree(self.unpack_directory)
                raise UnpackParserException("Cannot unpack 7z")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        if not self.encrypted:
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

    @property
    def labels(self):
        labels = ['7z', 'compressed', 'archive']
        if self.encrypted:
            labels.append('encrypted')
        return labels

    metadata = {}
