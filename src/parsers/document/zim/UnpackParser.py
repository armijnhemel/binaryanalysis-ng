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


import sys
import bz2
import hashlib
import lzma
import os
import zlib
import zstd

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import zim

from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_zim

class ZimUnpackParser(WrappedUnpackParser):
#class ZimUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5a\x49\x4d\x04')
    ]
    pretty_name = 'zim'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zim(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = zim.Zim.from_io(self.infile)
            # read data because Kaitai Struct evaluates instances lazily
            checksum = self.data.checksum

            for cluster in self.data.clusters.clusters:
                cluster_flag = cluster.cluster.flag
            self.unpacked_size = self.data.header.checksum + 16
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # compute the checksum
        self.infile.seek(0)

        bytes_left_to_read = self.unpacked_size - 16
        readsize = min(10240, bytes_left_to_read)
        bytebuffer = bytearray(readsize)
        zimmd5 = hashlib.new('md5')

        while True:
            bytesread = self.infile.readinto(bytebuffer)
            if bytesread == 0:
                break

            bufferlen = min(readsize, bytes_left_to_read)
            checkbytes = memoryview(bytebuffer[:bufferlen])
            zimmd5.update(checkbytes)
            bytes_left_to_read -= bufferlen
            if bytes_left_to_read == 0:
                break

        check_condition(zimmd5.digest() == self.data.checksum,
                        "checksum mismatch")

        num_entries = len(self.data.url_pointers.entries)
        num_clusters = len(self.data.clusters.clusters)
        for entry in self.data.url_pointers.entries:
            # sanity check: a redirect should point to
            # a valid index
            if type(entry.entry.body) == zim.Zim.Redirect:
                check_condition(entry.entry.body.redirect_index <= num_entries,
                                "invalid redirect index")
            else:
                check_condition(entry.entry.body.cluster_number < num_clusters,
                                "invalid cluster number")


    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['archive', 'zim']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
