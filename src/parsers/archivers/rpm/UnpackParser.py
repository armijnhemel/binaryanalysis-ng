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
import shutil
import tempfile

from bangunpack import unpack_gzip
from bangunpack import unpack_bzip2
from bangunpack import unpack_xz
from bangunpack import unpack_lzma
from bangunpack import unpack_zstd

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

        self.compressor_seen = False
        self.payload_format = ''
        # at most one compressor can be defined
        for i in self.data.header.index_records:
            if i.header_tag == rpm.Rpm.HeaderTags.payload_compressor:
                check_condition(not self.compressor_seen, "duplicate compressor defined")
                self.compressor_seen = True
            if i.header_tag == rpm.Rpm.HeaderTags.payload_format:
                check_condition(self.payload_format == '', "duplicate compressor defined")
                self.payload_format = i.body.values[0]


    def unpack(self):
        unpacked_files = []
        if self.payload_format not in ['cpio', 'drpm']:
            return unpacked_files

        # then unpack the file. This depends on the compressor and the
        # payload format.  The default compressor is either gzip or XZ
        # (on Fedora). Other supported compressors are bzip2, LZMA and
        # zstd (recent addition).
        if not self.compressor_seen:
            # if not defined fall back to gzip
            compressor = 'gzip'
        else:
            for i in self.data.header.index_records:
                if i.header_tag == rpm.Rpm.HeaderTags.payload_compressor:
                    compressor = i.body.values[0]
                    break

        # write the payload to a temporary file first
        temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
        os.write(temporary_file[0], self.data.payload)
        os.fdopen(temporary_file[0]).close()

        fr = FileResult(None, temporary_file[1], set([]))
        fr.set_filesize(len(self.data.payload))

        if compressor == 'gzip':
            unpackresult = unpack_gzip(fr, self.scan_environment, 0, self.rel_unpack_dir)
        elif compressor == 'bzip2':
            unpackresult = unpack_bzip2(fr, self.scan_environment, 0, self.rel_unpack_dir)
        elif compressor == 'xz':
            unpackresult = unpack_xz(fr, self.scan_environment, 0, self.rel_unpack_dir)
        elif compressor == 'lzma':
            unpackresult = unpack_lzma(fr, self.scan_environment, 0, self.rel_unpack_dir)
        elif compressor == 'zstd':
            unpackresult = unpack_zstd(fr, self.scan_environment, 0, self.rel_unpack_dir)
        else:
            # gzip is default
            unpackresult = unpack_gzip(fr, self.scan_environment, 0, self.rel_unpack_dir)
        os.unlink(temporary_file[1])

        payloadfile = unpackresult['filesandlabels'][0][0]
        payloadfile_full = self.scan_environment.unpack_path(payloadfile)

        if self.payload_format == 'drpm':
            fr = FileResult(self.fileresult, self.rel_unpack_dir / os.path.basename(payloadfile), set())
            unpacked_files.append(fr)
        else:
            # first move the payload file to a different location
            # to avoid any potential name clashes
            payloadsize = payloadfile_full.stat().st_size
            payloaddir = pathlib.Path(tempfile.mkdtemp(dir=self.scan_environment.temporarydirectory))
            shutil.move(str(payloadfile_full), payloaddir)

            # create a file result object and pass it to the CPIO unpacker
            fr = FileResult(self.fileresult,
                    payloaddir / os.path.basename(payloadfile),
                    set([]))
            fr.set_filesize(payloadsize)

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

            shutil.rmtree(payloaddir)

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
