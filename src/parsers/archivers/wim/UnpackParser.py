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
import shutil
import stat
import subprocess
import tempfile
import defusedxml

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    def unpack(self):
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        # check if the file starts at offset 0. If not, carve the
        # file first, as cabextract tries to be smart and unpack
        # all cab data in a file, like concatenated cab files,
        # even if there is other data in between the individual
        # cab files
        havetmpfile = False
        if not (self.offset == 0 and self.fileresult.filesize == self.unpacked_size):
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            havetmpfile = True
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

        if havetmpfile:
            p = subprocess.Popen(['7z', '-o%s' % unpackdir_full, '-y', 'x', temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['7z', '-o%s' % unpackdir_full, '-y', 'x', self.fileresult.filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        if havetmpfile:
            os.unlink(temporary_file[1])

        if p.returncode != 0:
            return unpacked_files

        # walk the results directory
        for result in unpackdir_full.glob('**/*'):
            # first change the permissions
            result.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            # then add the file to the result set
            file_path = result.relative_to(unpackdir_full)
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
            unpacked_files.append(fr)

        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    # no need to carve from the file
    def carve(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['mswim', 'archive']

        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
