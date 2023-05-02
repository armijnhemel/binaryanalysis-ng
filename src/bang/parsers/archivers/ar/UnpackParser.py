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

# Unix portable archiver
# https://en.wikipedia.org/wiki/Ar_%28Unix%29
# https://sourceware.org/binutils/docs/binutils/ar.html

import pathlib
import shutil
import stat
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class ArUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'!<arch>')
    ]
    pretty_name = 'ar'

    def parse(self):
        check_condition(shutil.which('ar') is not None,
                        "ar program not found")
        check_condition(self.offset == 0,
                        "Currently only works on whole files")
        p = subprocess.Popen(['ar', 't', self.infile.name], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (standard_out, standard_error) = p.communicate()

        check_condition(p.returncode == 0, "Not a valid ar file")

        self.debian = False
        if b'debian-binary' in standard_out:
            if meta_directory.file_path.suffix.lower() in ['.deb', '.udeb']:
                self.debian = True

        # try an actual unpack
        self.unpack_directory = pathlib.Path(tempfile.mkdtemp(dir=self.configuration.temporary_directory))

        p = subprocess.Popen(['ar', 'x', self.infile.name, '--output=%s' % self.unpack_directory],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()

        # TODO: look into cleanup if unpacking fails, is it necessary?
        if p.returncode != 0:
            shutil.rmtree(self.unpack_directory)
            raise UnpackParserException("Cannot unpack ar")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.size

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

    @property
    def labels(self):
        labels = ['archive', 'ar']
        if self.debian:
            labels.append('debian')
            labels.append('deb')
        return labels

    metadata = {}
