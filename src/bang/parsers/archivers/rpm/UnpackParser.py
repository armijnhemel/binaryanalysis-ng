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

import bz2
import gzip
import lzma
import pathlib
import zstandard

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import rpm
from . import rpm_no_utf8

ENCODINGS_TO_TRANSLATE = ['utf-8', 'ascii', 'latin-1', 'euc_jp', 'euc_jis_2004',
                          'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                          'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                          'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                          'shift_jis_2004', 'shift_jisx0213']

class RpmUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xed\xab\xee\xdb')
    ]
    pretty_name = 'rpm'

    def parse(self):
        try:
            self.data = rpm.Rpm.from_io(self.infile)

            # force read some of the header data as there might
            # be strings that are not UTF-8:
            # https://github.com/kaitai-io/kaitai_struct_formats/issues/672
            for i in self.data.header.index_records:
                i.body.values
        except UnicodeDecodeError as e:
            try:
                self.infile.seek(0)
                self.data = rpm_no_utf8.RpmNoUtf8.from_io(self.infile)
                for i in self.data.header.index_records:
                    if type(i.body) == self.data.RecordTypeStringArray:
                        new_values = []
                        for v in i.body.values:
                            success = False
                            for e in ENCODINGS_TO_TRANSLATE:
                                try:
                                    new_values.append(v.decode(e))
                                    success = True
                                    break
                                except:
                                    pass
                            check_condition(success, "cannot decode value")
                        # overwrite the old values with the new translated values
                        i.body.values = new_values
            except (Exception, ValidationFailedError) as e:
                raise UnpackParserException(e.args)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.data.lead.type == self.data.RpmTypes.binary or
                        self.data.lead.type == self.data.RpmTypes.source,
                        "invalid RPM type")

        # The default compressor is either gzip or XZ (on Fedora). Other
        # supported compressors are bzip2, LZMA and zstd (recent addition).
        # The default compressor is gzip.
        self.compressor = 'gzip'

        # at most one compressor and payload format can be defined
        self.compressor_seen = False
        self.payload_format = ''
        for i in self.data.header.index_records:
            if i.header_tag == self.data.HeaderTags.payload_compressor:
                check_condition(not self.compressor_seen, "duplicate compressor defined")
                self.compressor_seen = True
                self.compressor = i.body.values[0]
            if i.header_tag == self.data.HeaderTags.payload_format:
                check_condition(self.payload_format == '', "duplicate compressor defined")
                self.payload_format = i.body.values[0]

        check_condition(self.payload_format in ['cpio', 'drpm'],
                        'unsupported payload format')

        # test decompressing the payload
        if self.compressor == 'bzip2':
            decompressor = bz2.BZ2Decompressor()
            try:
                self.payload = decompressor.decompress(self.data.payload)
            except Exception as e:
                raise UnpackParserException(e.args)
        elif self.compressor == 'xz' or self.compressor == 'lzma':
            try:
                self.payload = lzma.decompress(self.data.payload)
            except Exception as e:
                raise UnpackParserException(e.args)
        elif self.compressor == 'zstd':
            try:
                reader = zstandard.ZstdDecompressor().stream_reader(self.data.payload)
                self.payload = reader.read()
            except Exception as e:
                raise UnpackParserException(e.args)
        else:
            try:
                self.payload = gzip.decompress(self.data.payload)
            except Exception as e:
                raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        if self.compressor == 'bzip2':
            decompressor = bz2.BZ2Decompressor()
            payload = decompressor.decompress(self.data.payload)
        elif self.compressor == 'xz' or self.compressor == 'lzma':
            payload = lzma.decompress(self.data.payload)
        elif self.compressor == 'zstd':
            reader = zstandard.ZstdDecompressor().stream_reader(self.data.payload)
            payload = reader.read()
        else:
            payload = gzip.decompress(self.data.payload)

        if self.payload_format == 'drpm':
            file_path = pathlib.Path('drpm')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(payload)
                yield unpacked_md
        else:
            file_path = pathlib.Path('cpio')
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                outfile.write(payload)
                yield unpacked_md

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.ofs_payload + len(self.data.payload)

    @property
    def labels(self):
        labels = [ 'rpm' ]
        if self.payload_format == 'drpm':
            labels.append('delta rpm')
        return labels

    @property
    def metadata(self):
        """sets metadata and labels for the unpackresults"""
        metadata = {}

        # store RPM version
        metadata['version'] = {}
        metadata['version']['major'] = self.data.lead.version.major
        metadata['version']['minor'] = self.data.lead.version.minor

        # store RPM type
        if self.data.lead.type == self.data.RpmTypes.binary:
            metadata['type'] = 'binary'
        else:
            metadata['type'] = 'source'

        # store signature tags
        metadata['signature_tags'] = {}
        for i in self.data.signature.index_records:
            metadata['signature_tags'][i.signature_tag.value] = i.body.values

        # store header tags
        metadata['header_tags'] = {}
        for i in self.data.header.index_records:
            metadata['header_tags'][i.header_tag.value] = i.body.values

        return metadata
