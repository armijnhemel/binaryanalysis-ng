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

# /usr/share/magic
# https://en.wikipedia.org/wiki/Compress
# https://github.com/vapier/ncompress/releases
# https://wiki.wxwidgets.org/Development:_Z_File_Format


import os
import pathlib
import subprocess
import shutil
import tempfile

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class CompressUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1f\x9d')
    ]
    pretty_name = 'compress'

    def parse(self):
        if shutil.which('uncompress') is None:
            check_condition(shutil.which('uncompress-ncompress') is not None,
                            'uncompress program not found')
            uncompress = 'uncompress-ncompress'
        else:
            uncompress = 'uncompress'

        bytes_read = 0
        self.infile.seek(2, os.SEEK_CUR)

        # the next byte contains the "bits per code" field
        # which has to be between 9 (inclusive) and 16 (inclusive)
        flags = self.infile.peek(1)
        check_condition(len(flags) != 0, 'no flags read')

        bitspercode = flags[0] & 0x1f
        check_condition(bitspercode >= 9 and bitspercode <= 16,
                        'invalid bits per code')

        # seek back to the starting point
        self.infile.seek(-2, os.SEEK_CUR)

        # like deflate compress can work on streams
        # As a test some data can be uncompressed.
        # read some test data
        testdata = self.infile.read(1024)

        # ...and run 'uncompress' to see if anything can be compressed at all
        p = subprocess.Popen([uncompress], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (standard_out, standard_error) = p.communicate(testdata)
        check_condition(len(standard_out) != 0, 'invalid compress\'d data')

        # then try to uncompress the whole file and write to /dev/null
        if self.offset == 0:
            p = subprocess.Popen(['uncompress', '-c', self.fileresult.filename],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            (standard_out, standard_error) = p.communicate()
            check_condition(p.returncode == 0 and standard_error == b'',
                            'invalid compress file')
            self.unpacked_size = self.fileresult.filesize
        else:
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.fileresult.filesize - self.offset)
            os.fdopen(temporary_file[0]).close()

            p = subprocess.Popen(['uncompress', '-c', temporary_file[1]],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            (standard_out, standard_error) = p.communicate()
            os.unlink(temporary_file[1])

            check_condition(p.returncode == 0 and standard_error == b'',
                            'invalid compress file')
            self.unpacked_size = self.fileresult.filesize - self.offset


    def unpack(self):
        unpacked_files = []
        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        out_labels = []

        # determine the name of the output file
        if self.fileresult.filename.suffix.lower() == '.z':
            file_path = pathlib.Path(self.fileresult.filename.stem)
        elif self.fileresult.filename.suffix.lower() == '.tz':
            file_path = pathlib.Path(self.fileresult.filename).with_suffix('.tar')
        else:
            file_path = pathlib.Path("unpacked_from_compress")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        # check if the file starts at offset 0. If not, carve the
        # file first, as uncompress cannot unpack the data otherwise
        havetmpfile = False
        if not (self.offset == 0 and self.fileresult.filesize == self.unpacked_size):
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

        if havetmpfile:
            p = subprocess.Popen(['uncompress', '-c', temporary_file[1]],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['uncompress', '-c', self.fileresult.filename],
                                 stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()
        outfile.close()

        if havetmpfile:
            os.unlink(temporary_file[1])

        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
        unpacked_files.append(fr)

        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['compress']

        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
