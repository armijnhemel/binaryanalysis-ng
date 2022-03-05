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
import os
import pathlib
import shutil
import tempfile
import zstandard

from parsers.archivers.cpio import UnpackParser as cpio_unpack

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import rpm

class RpmUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xed\xab\xee\xdb')
    ]
    pretty_name = 'rpm'

    def parse(self):
        file_size = self.fileresult.filename.stat().st_size
        try:
            self.data = rpm.Rpm.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.data.lead.type == rpm.Rpm.RpmTypes.binary or
                        self.data.lead.type == rpm.Rpm.RpmTypes.source,
                        "invalid RPM type")

        # The default compressor is either gzip or XZ (on Fedora). Other
        # supported compressors are bzip2, LZMA and zstd (recent addition).
        # The default compressor is gzip.
        self.compressor = 'gzip'

        # at most one compressor and payload format can be defined
        self.compressor_seen = False
        self.payload_format = ''
        for i in self.data.header.index_records:
            if i.header_tag == rpm.Rpm.HeaderTags.payload_compressor:
                check_condition(not self.compressor_seen, "duplicate compressor defined")
                self.compressor_seen = True
                self.compressor = i.body.values[0]
            if i.header_tag == rpm.Rpm.HeaderTags.payload_format:
                check_condition(self.payload_format == '', "duplicate compressor defined")
                self.payload_format = i.body.values[0]

        # test decompress the payload
        if self.compressor == 'bzip2':
            decompressor = bz2.BZ2Decompressor()
            try:
                payload = decompressor.decompress(self.data.payload)
            except Exception as e:
                raise UnpackParserException(e.args)
        elif self.compressor == 'xz' or self.compressor == 'lzma':
            try:
                payload = lzma.decompress(self.data.payload)
            except Exception as e:
                raise UnpackParserException(e.args)
        elif self.compressor == 'zstd':
            try:
                reader = zstandard.ZstdDecompressor().stream_reader(self.data.payload)
                payload = reader.read()
            except Exception as e:
                raise UnpackParserException(e.args)
        else:
            try:
                payload = gzip.decompress(self.data.payload)
            except Exception as e:
                raise UnpackParserException(e.args)

    def unpack(self):
        unpacked_files = []
        if self.payload_format not in ['cpio', 'drpm']:
            return unpacked_files

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
            out_labels = []
            file_path = pathlib.Path('drpm')
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            outfile.write(payload)
            outfile.close()
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        else:
            # write the payload to a temporary file first
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.write(temporary_file[0], payload)
            os.fdopen(temporary_file[0]).close()

            payloadfile = temporary_file[1]
            payloadfile_full = self.scan_environment.unpack_path(payloadfile)

            # create a file result object and pass it to the CPIO unpacker
            fr = FileResult(self.fileresult,
                    payloadfile,
                    set([]))
            fr.set_filesize(len(payload))

            # assuming that the CPIO data is always in "new ascii" format
            cpio_parser = cpio_unpack.CpioNewAsciiUnpackParser(fr, self.scan_environment, self.rel_unpack_dir, 0)
            try:
                cpio_parser.open()
                unpackresult = cpio_parser.parse_and_unpack()
            except UnpackParserException as e:
                raise UnpackParserException(e.args)
            finally:
                cpio_parser.close()

            # walk the results and add them.
            for i in unpackresult.unpacked_files:
                i.parent_path = self.fileresult.filename
                unpacked_files.append(i)

        return(unpacked_files)


    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.ofs_payload + len(self.data.payload)

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
        metadata['signature_tags'] = {}
        for i in self.data.signature.index_records:
            metadata['signature_tags'][i.signature_tag.value] = i.body.values

        # store header tags
        metadata['header_tags'] = {}
        for i in self.data.header.index_records:
            metadata['header_tags'][i.header_tag.value] = i.body.values

        if self.payload_format == 'drpm':
            labels.append('delta rpm')

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
