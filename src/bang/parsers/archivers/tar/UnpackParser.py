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

import pathlib
import stat
import tarfile

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException


class TarUnpackParser(UnpackParser):
    extensions = ['.tar']
    extensions = []
    signatures = [
        (0x101, b'ustar\x00'),
        (0x101, b'ustar\x20\x20\x00')
    ]
    pretty_name = 'tar'

    def parse(self):
        try:
            self.unpacktar = tarfile.open(fileobj=self.infile, mode='r')
        except tarfile.TarError as e:
            raise UnpackParserException(e.args)
        try:
            self.tarinfos = self.unpacktar.getmembers()
        except tarfile.TarError as e:
            raise UnpackParserException(e.args)

        tar_filenames = set()
        for tarinfo in self.tarinfos:
            file_path = pathlib.Path(tarinfo.name)

            # TODO: rename files properly with minimum chance of clashes
            if tarinfo.name in tar_filenames:
                pass
            if tarinfo.name in ['', ',', '..', '/']:
                pass
            if '\x00' in str(tarinfo.name):
                pass
            tar_filenames.add(tarinfo.name)

        # There could be additional padding as some tar implementations
        # align on blocks.
        #
        # Example: GNU tar tends to pad files with up to 20 blocks (512
        # bytes each) filled with 0x00 although this heavily depends on
        # the command line settings.
        #
        # This can be checked with GNU tar by inspecting the file with the
        # options "itvRf" to the tar command:
        #
        # $ tar itvRf /path/to/tar/file
        #
        # These padding bytes are not read by Python's tarfile module and
        # need to be explicitly checked and flagged as part of the file
        self.unpacked_size = self.infile.tell()

        if self.unpacked_size % 512 == 0:
            while self.unpacked_size < self.infile.size:
                checkbytes = self.infile.read(512)
                if len(checkbytes) != 512:
                    break
                if checkbytes != b'\x00' * 512:
                    break
                self.unpacked_size += 512

    def tar_unpack_regular(self, meta_directory, path, tarinfo):
        with meta_directory.unpack_regular_file(path) as (unpacked_md, f):
            tar_reader = self.unpacktar.extractfile(tarinfo)
            f.write(tar_reader.read())
            yield unpacked_md

    def unpack(self, meta_directory):
        for tarinfo in self.tarinfos:

            file_path = pathlib.Path(tarinfo.name)
            if tarinfo.isfile() or tarinfo.issym() or tarinfo.isdir() or tarinfo.islnk():
                if tarinfo.name == '':
                    # empty name, TODO
                    # test file pax-global-records.tar from golang-1.15-src_1.15.9-6_amd64.deb
                    continue
                if tarinfo.name in ['.', '..', '/']:
                    continue

                try:
                    if tarinfo.isfile(): # normal file
                        yield from self.tar_unpack_regular(meta_directory, file_path, tarinfo)
                    elif tarinfo.issym(): # symlink
                        target = pathlib.Path(tarinfo.linkname)
                        meta_directory.unpack_symlink(file_path, target)
                    elif tarinfo.islnk(): # hard link
                        target = pathlib.Path(tarinfo.linkname)
                        meta_directory.unpack_hardlink(file_path, target)
                    elif tarinfo.isdir(): # directory
                        meta_directory.unpack_directory(pathlib.Path(tarinfo.name))
                except ValueError:
                    # embedded NUL bytes could cause the extractor to fail
                    continue
            else:
                # block/device characters, sockets, etc. TODO
                pass

    def calculate_unpacked_size(self):
        pass

    labels = ['tar', 'archive']
    metadata = {}
