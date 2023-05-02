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

# Windows Imaging Format
#
# This format has been described by Microsoft here:
#
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749478(v=ws.10)
#
# but is currently not under the open specification promise
#
# Windows data types can be found here:
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx

import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import defusedxml

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import wim


class WimUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MSWIM\x00\x00\x00')
    ]
    pretty_name = 'mswim'

    def parse(self):
        if shutil.which('7z') is None:
            raise UnpackParserException("7z not installed")
        try:
            self.data = wim.Wim.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        if self.data.header.xml != b'':
            try:
                wimxml = self.data.header.xml.decode('utf_16_le')
            except UnicodeDecodeError as e:
                raise UnpackParserException(e.args)

            try:
                defusedxml.minidom.parseString(wimxml)
            except Exception as e:
                raise UnpackParserException(e.args)

        # record the maximum offset
        self.unpacked_size = max(self.infile.tell(),
                                 self.data.header.ofs_table.offset + self.data.header.ofs_table.size,
                                 self.data.header.xml_metadata.offset + self.data.header.xml_metadata.size,
                                 self.data.header.boot_metadata.offset + self.data.header.boot_metadata.size,
                                 self.data.header.integrity.offset + self.data.header.integrity.size,
                               )

        # test unpacking here. This is a little bit involved.
        # First check if the file starts at offset 0. If not, carve the
        # file first, as 7z tries to be smart and unpack
        # all wim data in a file.
        self.havetmpfile = False
        if not (self.offset == 0 and self.infile.size == self.unpacked_size):
            temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            havetmpfile = True
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

        # create a temporary unpacking directory to write results to
        self.unpack_directory = pathlib.Path(tempfile.mkdtemp(dir=self.configuration.temporary_directory))

        if self.havetmpfile:
            p = subprocess.Popen(['7z', '-o%s' % self.unpack_directory, '-y', 'x', temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['7z', '-o%s' % self.unpack_directory, '-y', 'x', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if self.havetmpfile:
            os.unlink(self.temporary_file[1])

        if p.returncode != 0:
            shutil.rmtree(self.unpack_directory)
            raise UnpackParserException("7z failed unpacking WIM")

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

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['mswim', 'archive']
    metadata = {}
