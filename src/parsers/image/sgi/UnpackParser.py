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
import tempfile

import PIL.Image

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import sgi


class SgiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x01\xda')
    ]
    pretty_name = 'sgi'

    def parse(self):
        try:
            self.unpacked_size = 0
            self.data = sgi.Sgi.from_io(self.infile)
            if self.data.header.storage_format == sgi.Sgi.StorageFormat.rle:
                for i in range(0, len(self.data.body.start_table_entries)):
                    self.unpacked_size = max(self.unpacked_size, self.data.body.start_table_entries[i] + self.data.body.length_table_entries[i])
                for scanline in self.data.body.scanlines:
                    # read data because Kaitai Struct evaluates instances lazily
                    len_data = len(scanline.data)
                check_condition(self.unpacked_size <= self.fileresult.filesize,
                            "data cannot be outside of file")
            else:
                self.unpacked_size = self.infile.tell()
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        if self.unpacked_size == self.fileresult.filesize:
            # now load the file using PIL as an extra sanity check
            # although this doesn't seem to do a lot.
            try:
                testimg = PIL.Image.open(self.infile)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
        else:
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

            # reopen as read only
            sgi_file = open(temporary_file[1], 'rb')
            try:
                testimg = PIL.Image.open(sgi_file)
                testimg.load()
                testimg.close()
            except OSError as e:
                raise UnpackParserException(e.args)
            finally:
                sgi_file.close()
                os.unlink(temporary_file[1])


    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['graphics', 'sgi']
        metadata = {}

        # TODO: write the file under the original name if available
        if self.data.header.name != '' and self.data.header.name != 'no name':
            metadata['name'] = self.data.header.name

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
