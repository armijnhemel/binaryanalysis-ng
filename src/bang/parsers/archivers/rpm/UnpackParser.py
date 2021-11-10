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
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_rpm
from bangunpack import unpack_gzip
from bangunpack import unpack_bzip2
from bangunpack import unpack_xz
from bangunpack import unpack_lzma
from bangunpack import unpack_zstd

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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
        try:
            self.data = rpm.Rpm.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.data.lead.type == rpm.Rpm.RpmTypes.binary or
                        self.data.lead.type == rpm.Rpm.RpmTypes.source,
                        "invalid RPM type")

        # extract the header + payload size, calculate the payload size
        rpmsize = 0
        for i in self.data.signature.index_records:
            if i.tag == rpm.Rpm.SignatureTags.size:
                rpmsize = i.body.values[0]
        self.payload_size = rpmsize - self.data.header.header_size
        check_condition(self.data.payload_offset + self.payload_size <= self.infile.size,
                        "payload cannot be outside of file")

        self.compressor_seen = False
        self.payload_format = ''
        # at most one compressor can be defined
        for i in self.data.header.index_records:
            if i.tag == rpm.Rpm.HeaderTags.payload_compressor:
                check_condition(not self.compressor_seen, "duplicate compressor defined")
                self.compressor_seen = True
            if i.tag == rpm.Rpm.HeaderTags.payload_format:
                check_condition(self.payload_format == '', "duplicate compressor defined")
                self.payload_format = i.body.values[0]


    def unpack(self, unpack_directory):
        unpacked_files = []
        if self.payload_format != 'cpio':
            return(unpacked_files)

        # then unpack the file. This depends on the compressor and the
        # payload format.  The default compressor is either gzip or XZ
        # (on Fedora). Other supported compressors are bzip2, LZMA and
        # zstd (recent addition).
        if not self.compressor_seen:
            # if not defined fall back to gzip
            compressor = 'gzip'
        else:
            for i in self.data.header.index_records:
                if i.tag == rpm.Rpm.HeaderTags.payload_compressor:
                    compressor = i.body.values[0]
                    break
        offset = self.offset + self.data.payload_offset
        if compressor == 'gzip':
            unpackresult = unpack_gzip(self.fileresult, self.scan_environment, offset, self.rel_unpack_dir)
        elif compressor == 'bzip2':
            unpackresult = unpack_bzip2(self.fileresult, self.scan_environment, offset, self.rel_unpack_dir)
        elif compressor == 'xz':
            unpackresult = unpack_xz(self.fileresult, self.scan_environment, offset, self.rel_unpack_dir)
        elif compressor == 'lzma':
            unpackresult = unpack_lzma(self.fileresult, self.scan_environment, offset, self.rel_unpack_dir)
        elif compressor == 'zstd':
            unpackresult = unpack_zstd(self.fileresult, self.scan_environment, offset, self.rel_unpack_dir)
        else:
            # gzip is default
            unpackresult = unpack_gzip(self.fileresult, self.scan_environment, offset, self.rel_unpack_dir)

        payloadfile = rpmunpackfiles[0][0]
        payloadfile_full = scanenvironment.unpack_path(payloadfile)

        # first move the payload file to a different location
        # to avoid any potential name clashes
        payloadsize = payloadfile_full.stat().st_size
        payloaddir = pathlib.Path(tempfile.mkdtemp(dir=scanenvironment.temporarydirectory))
        shutil.move(str(payloadfile_full), payloaddir)

        # create a file result object and pass it to the CPIO unpacker
        fr = FileResult(fileresult,
                payloaddir / os.path.basename(payloadfile),
                set([]))
        fr.set_filesize(payloadsize)
        unpackresult = unpack_cpio(fr, scanenvironment, 0, unpackdir)
        # cleanup
        shutil.rmtree(payloaddir)
        if not unpackresult['status']:
            checkfile.close()
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'could not unpack CPIO payload'}
            return {'status': False, 'error': unpackingerror}
        for i in unpackresult['filesandlabels']:
            # TODO: is normpath necessary now that we use relative paths?
            unpackedfilesandlabels.append((os.path.normpath(i[0]), i[1]))

        return unpacked_files

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.payload_offset + self.payload_size

    @property
    def labels(self):
        labels = [ 'rpm' ]
        if self.payload_format == 'drpm':
            payloadfile_rel = scanenvironment.rel_unpack_path(payloadfile)
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
        if self.data.lead.type == rpm.Rpm.RpmTypes.binary:
            metadata['type'] = 'binary'
        else:
            metadata['type'] = 'source'

        # store signature tags
        metadata['signature_tags'] = {}
        for i in self.data.signature.index_records:
            metadata['signature_tags'][i.tag.value] = i.body.values

        # store header tags
        metadata['header_tags'] = {}
        for i in self.data.header.index_records:
            metadata['header_tags'][i.tag.value] = i.body.values

        return metadata

