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
import hashlib
import lzma
import os
import zlib

import zstandard

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import zim

SKIPPABLE = [zim.Zim.Namespace.metadata,
             zim.Zim.Namespace.article_meta_data,
             zim.Zim.Namespace.search_indexes,
             zim.Zim.Namespace.xapian_indexes]

class ZimUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5a\x49\x4d\x04')
    ]
    pretty_name = 'zim'

    def parse_cluster_data(self, cluster_data, offset_size):
        # first offset can be used to calculate the number of blobs
        first_offset = int.from_bytes(cluster_data[:offset_size], byteorder='little')
        num_blobs = first_offset//offset_size

        # sanity check for blobs. These are used to compute the offsets and
        # sizes of blobs.
        # The last pointer points to the end of the data area
        # There is always one more offset than blobs.

        offsets = []
        len_cluster_data = len(cluster_data)
        for i in range(num_blobs):
            offset = int.from_bytes(cluster_data[i*offset_size:i*offset_size+offset_size], byteorder='little')
            check_condition(offset <= len_cluster_data, "invalid blob offset")
            offsets.append(offset)
        return offsets

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

        # sanity checks for compressed data
        blobs_per_cluster = {}
        cluster_count = 0
        for cluster in self.data.clusters.clusters:
            offset_size = cluster.cluster.flag.offset_size
            if cluster.cluster.flag.compressed == zim.Zim.Compression.zstd:
                try:
                    reader = zstandard.ZstdDecompressor().stream_reader(cluster.cluster.body.data)
                    cluster_data = reader.read()
                except Exception as e:
                    raise UnpackParserException(e.args)
                blobs = self.parse_cluster_data(cluster_data, offset_size)
                blobs_per_cluster[cluster_count] = len(blobs) - 1
            elif cluster.cluster.flag.compressed == zim.Zim.Compression.xz:
                decompressor = lzma.LZMADecompressor()
                try:
                    cluster_data = decompressor.decompress(cluster.cluster.body.data)
                except Exception as e:
                    raise UnpackParserException(e.args)
                blobs = self.parse_cluster_data(cluster_data, offset_size)
                blobs_per_cluster[cluster_count] = len(blobs) - 1
            elif cluster.cluster.flag.compressed == zim.Zim.Compression.zlib:
                decompressor = zlib.decompressobj()
                try:
                    cluster_data = decompressor.decompress(cluster.cluster.body.data)
                except Exception as e:
                    raise UnpackParserException(e.args)
                blobs = self.parse_cluster_data(cluster_data, offset_size)
                blobs_per_cluster[cluster_count] = len(blobs) - 1
            elif cluster.cluster.flag.compressed == zim.Zim.Compression.bzip2:
                decompressor = bz2.BZ2Decompressor()
                try:
                    cluster_data = decompressor.decompress(cluster.cluster.body.data)
                except Exception as e:
                    raise UnpackParserException(e.args)
                blobs = self.parse_cluster_data(cluster_data, offset_size)
                blobs_per_cluster[cluster_count] = len(blobs) - 1
            else:
                blobs_per_cluster[cluster_count] = len(cluster.cluster.body.blobs)
            cluster_count += 1

        # sanity checks for URL pointers
        num_entries = len(self.data.url_pointers.entries)
        num_clusters = len(self.data.clusters.clusters)
        for entry in self.data.url_pointers.entries:
            check_condition(entry.entry.body.namespace != zim.Zim.Namespace.unknown,
                            "cannot process unknown namespace")

            # sanity check: a redirect should point to
            # a valid index
            if type(entry.entry.body) == zim.Zim.Redirect:
                check_condition(entry.entry.body.redirect_index <= num_entries,
                                "invalid redirect index")
            else:
                check_condition(entry.entry.body.cluster_number < num_clusters,
                                "invalid cluster number")
                check_condition(entry.entry.body.blob_number < blobs_per_cluster[entry.entry.body.cluster_number],
                                "invalid blob number")


    def unpack(self):
        unpacked_files = []

        cluster_count = 0
        blobs_per_compressed_cluster = {}
        cluster_to_data = {}

        for cluster in self.data.clusters.clusters:
            offset_size = cluster.cluster.flag.offset_size
            if cluster.cluster.flag.compressed == zim.Zim.Compression.no_compression:
                cluster_count += 1
                continue
            if cluster.cluster.flag.compressed == zim.Zim.Compression.no_compression2:
                cluster_count += 1
                continue

            if cluster.cluster.flag.compressed == zim.Zim.Compression.zstd:
                reader = zstandard.ZstdDecompressor().stream_reader(cluster.cluster.body.data)
                cluster_data = reader.read()

            elif cluster.cluster.flag.compressed == zim.Zim.Compression.xz:
                decompressor = lzma.LZMADecompressor()
                cluster_data = decompressor.decompress(cluster.cluster.body.data)

            elif cluster.cluster.flag.compressed == zim.Zim.Compression.zlib:
                decompressor = zlib.decompressobj()
                cluster_data = decompressor.decompress(cluster.cluster.body.data)

            elif cluster.cluster.flag.compressed == zim.Zim.Compression.bzip2:
                decompressor = bz2.BZ2Decompressor()
                cluster_data = decompressor.decompress(cluster.cluster.body.data)

            offsets = self.parse_cluster_data(cluster_data, offset_size)
            blobs = []
            for i in range(len(offsets)-1):
                start = offsets[i]
                end = offsets[i+1]
                blobs.append(cluster_data[start:end])

            blobs_per_compressed_cluster[cluster_count] = blobs

            cluster_count += 1

        entry_counter = 0
        for entry in self.data.url_pointers.entries:
            if type(entry.entry.body) == zim.Zim.Redirect:
                if entry.entry.body.url != '':
                    name = entry.entry.body.url
                elif entry.entry.body.title != '':
                    name = entry.entry.body.title
                else:
                    continue

                # check if the content entry is actually content, or maybe metadata
                if self.data.url_pointers.entries[entry.entry.body.redirect_index].entry.body.namespace in SKIPPABLE:
                    continue

                if self.data.url_pointers.entries[entry.entry.body.redirect_index].entry.body.url != '':
                    target = self.data.url_pointers.entries[entry.entry.body.redirect_index].entry.body.url
                elif self.data.url_pointers.entries[entry.entry.body.redirect_index].entry.body.title != '':
                    target = self.data.url_pointers.entries[entry.entry.body.redirect_index].entry.body.title
                else:
                    continue

                # TODO: both name and target are relative to the root
                # this means that a relative path from name to target
                # should be computed first.
                outfile_rel = self.rel_unpack_dir / name
                outfile_full = self.scan_environment.unpack_path(outfile_rel)

                # check if a directory component already exists as a regular file.
                # This should not happen, but Zim allows for this. Example:
                # zdoom_en_all_nopic_2021-10.zim
                try:
                    os.makedirs(outfile_full.parent, exist_ok=True)
                except:
                    continue
                outfile_full.symlink_to(target)
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                unpacked_files.append(fr)
            else:
                if entry.entry.body.namespace in SKIPPABLE:
                    continue

                if entry.entry.body.url != '':
                    name = entry.entry.body.url
                elif entry.entry.body.title != '':
                    name = entry.entry.body.title
                else:
                    continue

                outfile_rel = self.rel_unpack_dir / name
                outfile_full = self.scan_environment.unpack_path(outfile_rel)

                # check if a directory component already exists as a regular file.
                # This should not happen, but Zim allows for this. Example:
                # zdoom_en_all_nopic_2021-10.zim
                try:
                    os.makedirs(outfile_full.parent, exist_ok=True)
                except:
                    continue
                outfile = open(outfile_full, 'wb')

                if entry.entry.body.cluster_number not in blobs_per_compressed_cluster:
                    # not in a compressed cluster, so easy to process
                    outfile.write(self.data.clusters.clusters[entry.entry.body.cluster_number].cluster.body.blobs[entry.entry.body.blob_number].blob)
                else:
                    outfile.write(blobs_per_compressed_cluster[entry.entry.body.cluster_number][entry.entry.body.blob_number])
                outfile.close()
                fr = FileResult(self.fileresult, outfile_rel, set([]))
                unpacked_files.append(fr)
            entry_counter += 1

        return unpacked_files


    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['archive', 'zim']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
