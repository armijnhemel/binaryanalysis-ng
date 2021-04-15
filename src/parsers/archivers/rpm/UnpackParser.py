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
Parse and unpack RPM files.
'''


import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_rpm
from bangunpack import unpack_gzip
from bangunpack import unpack_bzip2
from bangunpack import unpack_xz
from bangunpack import unpack_lzma
from bangunpack import unpack_zstd

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import rpm

#class RpmUnpackParser(UnpackParser):
class RpmUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xed\xab\xee\xdb')
    ]
    pretty_name = 'rpm'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_rpm(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        file_size = self.fileresult.filename.stat().st_size
        try:
            self.data = rpm.Rpm.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.data.lead.type == rpm.Rpm.RpmTypes.binary or
                        self.data.lead.type == rpm.Rpm.RpmTypes.source,
                        "invalid RPM type")

        # extract the header + payload size
        rpmsize = 0
        for i in self.data.signature.index_records:
            if i.tag == rpm.Rpm.SignatureTags.size:
                rpmsize = i.body.values[0]

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'rpm' ]
        metadata = {}

        # store RPM version
        metadata['version'] = {}
        metadata['version']['major'] = self.data.lead.version.major
        metadata['version']['minor'] = self.data.lead.version.minor

        # store RPM type
        if self.data.lead.type == rpm.Rpm.RpmTypes.binary:
            metadata['type'] = 'binary'
        else:
            metadata['type'] = 'source'

        # store signature tags
        #metadata['signature_tags'] = {}
        #for i in self.data.signature.index_records:
        #    metadata['signature_tags'][i.tag.value] = i.body.values
        metadata['signature_tags'] = self.data.signature.index_records

        # store header tags
        #metadata['header_tags'] = {}
        #for i in self.data.header.index_records:
        #    metadata['header_tags'][i.tag.value] = i.body.values
        metadata['header_tags'] = self.data.header.index_records

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
