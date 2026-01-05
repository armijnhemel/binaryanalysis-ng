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

# /usr/share/magic
# https://en.wikipedia.org/wiki/Compress
# https://github.com/vapier/ncompress/releases
# https://wiki.wxwidgets.org/Development:_Z_File_Format

import os
import pathlib
import subprocess
import shutil
import tempfile

from bang.UnpackParser import UnpackParser, check_condition


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

        # check if the file starts at offset 0. If not, carve the
        # file first, as uncompress cannot unpack the data otherwise
        self.havetmpfile = False

        # then try to uncompress the whole file and write to /dev/null
        if self.offset == 0:
            p = subprocess.Popen(['uncompress', '-c', self.infile.name],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            (standard_out, standard_error) = p.communicate()
            check_condition(p.returncode == 0 and standard_error == b'',
                            'invalid compress file')
        else:
            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)
            os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.infile.size)
            os.fdopen(self.temporary_file[0]).close()

            p = subprocess.Popen(['uncompress', '-c', self.temporary_file[1]],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            (standard_out, standard_error) = p.communicate()

            if p.returncode != 0 or standard_error != b'':
                os.unlink(self.temporary_file[1])

            check_condition(p.returncode == 0 and standard_error == b'',
                            'invalid compress file')

            self.havetmpfile = True
        self.unpacked_size = self.infile.size

    def unpack(self, meta_directory):
        # determine the name of the output file
        if meta_directory.file_path.suffix.lower() == '.z':
            file_path = pathlib.Path(meta_directory.file_path.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_compress")
        elif meta_directory.file_path.suffix.lower() in ['.tz', '.tarz']:
            file_path = pathlib.Path(meta_directory.file_path.filename).with_suffix('.tar')
        else:
            file_path = pathlib.Path("unpacked_from_compress")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            if self.havetmpfile:
                p = subprocess.Popen(['uncompress', '-c', self.temporary_file[1]],
                                     stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)
            else:
                p = subprocess.Popen(['uncompress', '-c', self.infile.name],
                                     stdin=subprocess.PIPE, stdout=outfile, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()

            if self.havetmpfile:
                os.unlink(self.temporary_file[1])
            yield unpacked_md

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['compress']
    metadata = {}
