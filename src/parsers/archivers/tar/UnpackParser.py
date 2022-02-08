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


import os
import pathlib
import tarfile

from UnpackParser import UnpackParser, WrappedUnpackParser
from UnpackParserException import UnpackParserException
from FileResult import FileResult
from bangunpack import unpack_tar

class wTarUnpackParser(WrappedUnpackParser):
    extensions = ['.tar']
    signatures = [
        (0x101, b'ustar\x00'),
        (0x101, b'ustar\x20\x20\x00')
    ]
    pretty_name = 'tar'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_tar(fileresult, scan_environment, offset, unpack_dir)


class TarUnpackParser(UnpackParser):
    #extensions = ['.tar']
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

    def tar_unpack_regular(self, outfile_rel, tarinfo):
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        tar_reader = self.unpacktar.extractfile(tarinfo)
        outfile.write(tar_reader.read())
        outfile.close()

    def unpack(self):
        unpacked_files = []
        for tarinfo in self.tarinfos:
            out_labels = []
            file_path = pathlib.Path(tarinfo.name)
            if file_path.is_absolute():
                file_path = file_path.relative_to('/')
                tarinfo.name = file_path
            outfile_rel = self.rel_unpack_dir / file_path
            if tarinfo.isfile(): # normal file
                self.tar_unpack_regular(outfile_rel, tarinfo)
                fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
                unpacked_files.append(fr)
            elif tarinfo.issym(): # symlink
                pass
            elif tarinfo.islnk(): # hard link
                pass
            elif tarinfo.isdir(): # directory
                pass

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['tar', 'archive']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
