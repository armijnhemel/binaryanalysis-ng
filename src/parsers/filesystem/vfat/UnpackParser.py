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
import struct
from . import vfat
from . import vfat_directory
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from FileResult import FileResult
from kaitaistruct import ValidationFailedError

# https://en.wikipedia.org/wiki/File_Allocation_Table
# https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system


def get_lfn_part(record):
    # note: because python lacks a ucs-2 decoder, we use utf-16. In almost all
    # cases, these encodings are the same.
    # See http://lucumr.pocoo.org/2014/1/9/ucs-vs-utf8/
    return (record.lfn_part1 + record.lfn_part2 + \
            record.lfn_part3).decode('utf-16').rstrip('\uffff').rstrip('\0')

def get_short_filename(record):
    fn = record.short_name.rstrip(b' ')
    ext = record.short_ext.rstrip(b' ')
    if ext:
        fn += b'.' + ext
    return fn.decode().lower()

class VfatUnpackParser(UnpackParser):
    pretty_name = 'fat'
    # FAT does not have a reliable signature
    # the best way to extract is from the context, i.e. knowing that this
    # is a FAT filesystem. We can use the 'file system type' string, but since
    # this was never intended as a signature, it is unreliable.
    signatures = [
            (54, b'FAT'),
            (82, b'FAT32   ')
            ]

    def parse(self):
        try:
            self.data = vfat.Vfat.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)
        bpb = self.data.boot_sector.bpb
        check_condition(bpb.ls_per_clus > 0, "invalid bpb value: ls_per_clus")
        check_condition(bpb.bytes_per_ls > 0, "invalid bpb value: bytes_per_ls")

        self.fat12 = False
        self.fat32 = self.data.boot_sector.is_fat32
        if not self.fat32:
            self.fat12 = self.is_fat12()

        self.pos_data = self.data.boot_sector.pos_root_dir + self.data.boot_sector.size_root_dir
        check_condition(self.pos_data <= self.fileresult.filesize,
                "data sector outside file")

    def calculate_unpacked_size(self):
        total_ls = max(self.data.boot_sector.bpb.total_ls_2,
                self.data.boot_sector.bpb.total_ls_4)
        self.unpacked_size = total_ls * self.data.boot_sector.bpb.bytes_per_ls

    def is_fat12(self):
        """Guesses whether the filesystem is FAT12 or not, based on the
        cluster count of the volume. For a description of the algorithm, see
        https://jdebp.eu/FGA/determining-fat-widths.html
        """
        total_ls = max(self.data.boot_sector.bpb.total_ls_2,
                self.data.boot_sector.bpb.total_ls_4)
        bpb = self.data.boot_sector.bpb
        data_start = bpb.num_reserved_ls + bpb.num_fats * bpb.ls_per_fat + self.data.boot_sector.ls_per_root_dir
        cluster_count = 2 + (total_ls - data_start) / bpb.ls_per_clus
        return cluster_count < 4087

    def get_fat12_entry(self, n):
        """Gets the entry from a FAT12 cluster map."""
        # http://dfists.ua.es/~gil/FAT12Description.pdf, p. 9
        if n & 0x01 == 0:
            return ((self.data.fats[0][1+((3*n)>>1)] & 0x0f) << 8) | \
                    self.data.fats[0][(3*n)>>1]
        return ((self.data.fats[0][(3*n)>>1] & 0xf0 ) >> 4 ) | \
            (self.data.fats[0][1+((3*n)>>1)] << 4)

    def get_fat16_entry(self, n):
        # return self.data.fats[0][2*n] | (self.data.fats[0][2*n + 1] << 8)
        return struct.unpack("<H", self.data.fats[0][2*n:2*n+2])[0]

    def get_fat32_entry(self, n):
        return struct.unpack("<I", self.data.fats[0][4*n:4*n+4])[0] & 0x0fffffff

    def unpack(self):
        try:
            unpacked_files = [
                x for x in self.unpack_directory(
                    self.data.root_dir.records, self.rel_unpack_dir)
            ]
        except BaseException as e:
            raise UnpackParserException(e.args)
        return unpacked_files

    def unpack_directory(self, directory_records, rel_unpack_dir):
        lfn = False
        fn = ''
        for record in directory_records:
            if not lfn:
                if record.is_lfn_entry:
                    lfn = True
                    fn = get_lfn_part(record)
                else:
                    fn = get_short_filename(record)
            else: # lfn
                if record.is_lfn_entry:

                    fn = get_lfn_part(record) + fn
                else:
                    lfn = False
                    pass # keep long filename
            if not lfn:
                if fn[0] == '\0': continue
                # get other attributes
                rel_outfile = rel_unpack_dir / fn
                if record.attr_subdirectory:
                    if fn != '.' and fn != '..':
                        dir_entries = self.extract_dir(
                                record.start_clus, rel_outfile)
                        # parse dir_entries and process
                        subdir = vfat_directory.VfatDirectory.from_bytes(dir_entries)
                        for unpacked_file in self.unpack_directory(
                                subdir.records, rel_outfile):
                            yield unpacked_file
                     
                else:
                    # TODO: if normal_file
                    yield self.extract_file(record.start_clus, record.file_size, rel_outfile)

    def extract_dir(self, start_cluster, rel_outfile):
        abs_outfile = self.scan_environment.unpack_path(rel_outfile)
        os.makedirs(abs_outfile, exist_ok=True)
        dir_entries = b''
        cluster_size = self.data.boot_sector.bpb.ls_per_clus * \
                self.data.boot_sector.bpb.bytes_per_ls
        for cluster in self.cluster_chain(start_cluster):
            start = self.pos_data + (cluster-2) * cluster_size
            check_condition(start+cluster_size <= self.fileresult.filesize,
                    "directory data outside file")
            self.infile.seek(start)
            dir_entries += self.infile.read(cluster_size)
        return dir_entries

    def extract_file(self, start_cluster, file_size, rel_outfile):
        abs_outfile = self.scan_environment.unpack_path(rel_outfile)
        os.makedirs(abs_outfile.parent, exist_ok=True)
        outfile = open(abs_outfile, 'wb')
        size_read = 0
        cluster_size = self.data.boot_sector.bpb.ls_per_clus * \
                self.data.boot_sector.bpb.bytes_per_ls
        for cluster in self.cluster_chain(start_cluster):
            bytes_to_read = min(cluster_size, file_size - size_read)
            start = self.pos_data + (cluster-2) * cluster_size
            check_condition(start+bytes_to_read <= self.fileresult.filesize,
                    "file data outside file")
            os.sendfile(outfile.fileno(), self.infile.fileno(), start + self.infile.offset, bytes_to_read)
            size_read += bytes_to_read
        outfile.close()
        outlabels = []
        return FileResult(self.fileresult, rel_outfile, set(outlabels))

    def is_end_cluster(self, cluster):
        # TODO: handle bad clusters and other exceptions
        if self.fat12:
            return cluster >= 0xff8
        if self.fat32:
            # return cluster >= 0x0ffffff8   # if cluster already masked
            return (cluster & 0xffffff8) == 0xffffff8
        return cluster >= 0xfff8

    def get_cluster_map_entry(self, cluster):
        if self.fat12:
            return self.get_fat12_entry(cluster)
        if self.fat32:
            return self.get_fat32_entry(cluster)
        return self.get_fat16_entry(cluster)

    def cluster_chain(self, start_cluster):
        cluster = start_cluster
        while not self.is_end_cluster(cluster):
            yield cluster
            cluster = self.get_cluster_map_entry(cluster)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['fat', 'filesystem']
        metadata = {}

        # store the OEM name. Even though the OEM name should be padded
        # with spaces sometimes there are NUL characters instead
        oem_name = self.data.boot_sector.oem_name.split('\x00')[0]

        metadata['oem'] = oem_name

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
