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
The Android A/B update format is either a full image or an update image.
The focus here is first on the full image. The specification cannot be
fully captured in Kaitai Struct as it part of the data structure is done
using Google Protobuf.

This parser uses both Kaitai Struct and a parser generated from the Protobuf
sources. Kaitai Struct is used for the first big sweep and several syntactical
checks. The Protobuf generated parsers is then used to extract the data.
'''

import bz2
import hashlib
import lzma
import os
import pathlib
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_update
from . import update_metadata_pb2


class AndroidUpdateUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'CrAU')
    ]
    pretty_name = 'android_update'

    def parse(self):
        try:
            self.data = android_update.AndroidUpdate.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # now parse the manifest data (version 1) or the partitions (version 2)
        try:
            self.manifest_data = update_metadata_pb2.DeltaArchiveManifest()
            self.manifest_data.ParseFromString(self.data.manifest)
        except Exception as e:
            raise UnpackParserException(e.args)

        # and the signatures
        try:
            self.signatures_data = update_metadata_pb2.Signatures()
            self.signatures_data.ParseFromString(self.data.manifest_signature)
        except Exception as e:
            raise UnpackParserException(e.args)

        self.start_of_payload = self.infile.tell()

        # then the payload_data
        if self.data.major_version == 2:
            block_size = self.manifest_data.block_size

            # signatures offset (relative to the start of the payload)
            signatures_offset = self.manifest_data.signatures_offset
            signatures_size = self.manifest_data.signatures_size
            check_condition(self.start_of_payload + signatures_offset + signatures_size <= self.fileresult.filesize,
                            "not enough data for signatures")

            minor_version = self.manifest_data.minor_version
            for partition in self.manifest_data.partitions:
                block_counter = 0
                for operation in partition.operations:
                    # operation offset is relative to the start of the payload
                    check_condition(self.start_of_payload + operation.data_offset + operation.data_length <= self.fileresult.filesize,
                                    "not enough data for operation")

                    # signatures follow the last block
                    check_condition(operation.data_offset + operation.data_length <= signatures_offset,
                                    "data blocks should appear before signatures")

                    check_condition(len(operation.dst_extents) == 1,
                                    "only full payloads supported")

                    # blocks should be sequential for a full update image
                    check_condition(operation.dst_extents[0].start_block == block_counter,
                                    "data blocks not sequential")
                    block_counter = operation.dst_extents[0].start_block + operation.dst_extents[0].num_blocks

                    # check the sha256 hash of the data block
                    self.infile.seek(self.start_of_payload + operation.data_offset)
                    data = self.infile.read(operation.data_length)
                    data_sha256 = hashlib.new('sha256')
                    data_sha256.update(data)
                    check_condition(data_sha256.digest() == operation.data_sha256_hash,
                                    "data hash mismatch")

            # and finally the signatures
            try:
                self.infile.seek(self.start_of_payload + signatures_offset)
                signatures = self.infile.read(signatures_size)
                signatures = update_metadata_pb2.Signatures()
                signatures.ParseFromString(self.data.manifest_signature)
            except Exception as e:
                raise UnpackParserException(e.args)


    # no need to carve from the file
    def carve(self):
        pass

    def unpack(self):
        unpacked_files = []
        if self.data.major_version == 2:
            for partition in self.manifest_data.partitions:
                out_labels = []
                file_path = partition.partition_name
                outfile_rel = self.rel_unpack_dir / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')

                for operation in partition.operations:
                    self.infile.seek(self.start_of_payload + operation.data_offset)
                    data = self.infile.read(operation.data_length)
                    if operation.type == update_metadata_pb2.InstallOperation.Type.REPLACE:
                        outfile.write(data)
                    elif operation.type == update_metadata_pb2.InstallOperation.Type.REPLACE_BZ:
                        decompressor = bz2.BZ2Decompressor()
                        outfile.write(decompressor.decompress(data))
                    elif operation.type == update_metadata_pb2.InstallOperation.Type.REPLACE_XZ:
                        decompressor = lzma.LZMADecompressor()
                        outfile.write(decompressor.decompress(data))
                        pass
                    else:
                        pass
                outfile.close()
                fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
                unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android update image', 'android']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
