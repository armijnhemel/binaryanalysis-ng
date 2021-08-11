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

'''
Parse and unpack PE files.
'''

import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import microsoft_pe


class PeClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MZ')
    ]
    pretty_name = 'pe'

    def parse(self):
        self.file_size = self.fileresult.filesize
        try:
            self.data = microsoft_pe.MicrosoftPe.from_io(self.infile)
            # this is a bit of an ugly hack to detect if the file
            # has been truncated. Also: certain packers screw around
            # with the values of the PE headers
            for s in self.data.pe.sections:
                pass
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.mz.ofs_pe <= self.file_size,
                "invalid offset")

    def calculate_unpacked_size(self):
        # calculate the size of the PE. This is somewhat
        # involved as there are multiple headers involved.
        self.unpacked_size = self.data.mz.ofs_pe
        for s in self.data.pe.sections:
            self.unpacked_size = max(self.unpacked_size, s.size_of_raw_data + s.pointer_to_raw_data)

        # certificates, if any, are appended at the end of the file
        if self.data.pe.certificate_table is not None:
            certificate = self.data.pe.optional_hdr.data_dirs.certificate_table
            self.unpacked_size = max(self.unpacked_size, certificate.virtual_address + certificate.size)

        # extra data could follow the PE, such as information
        # from installers or other extra data. It is impossible
        # to get this information from the PE headers, so other
        # tricks need to be found. TODO.

    def unpack(self):
        """extract any files from the input file"""
        return []

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'pe', 'executable' ]
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
