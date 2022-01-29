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


import os
import shutil
import stat
import subprocess

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

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
        p = subprocess.Popen(['ar', 't', self.fileresult.filename], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (standard_out, standard_error) = p.communicate()

        check_condition(p.returncode == 0, "Not a valid ar file")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.fileresult.filesize

    def unpack(self):
        unpacked_files = []
        out_labels = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        p = subprocess.Popen(['ar', 'x', self.fileresult.filename, '--output=%s' % unpackdir_full],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()
        # TODO: look into cleanup if unpacking fails, is it necessary?
        check_condition(p.returncode == 0, "Not a valid ar file")

        # walk the results directory
        for result in unpackdir_full.glob('**/*'):
            # first change the permissions
            result.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            # then add the file to the result set
            file_path = result.relative_to(unpackdir_full)
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
            unpacked_files.append(fr)

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['archive', 'ar']
        metadata = {}

        p = subprocess.Popen(['ar', 't', self.fileresult.filename], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (standard_out, standard_error) = p.communicate()

        if b'debian-binary' in standard_out:
            if self.fileresult.filename.suffix.lower() in ['.deb', '.udeb']:
                labels.append('debian')
                labels.append('deb')

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
