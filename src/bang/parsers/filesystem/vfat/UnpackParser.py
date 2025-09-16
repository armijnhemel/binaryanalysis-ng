# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

import os
import struct
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from bang.log import log
from kaitaistruct import ValidationFailedError

from . import vfat
from . import vfat_directory

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
        except (ValidationFailedError, Exception, BaseException) as e:
            raise UnpackParserException(e.args) from e
        bpb = self.data.boot_sector.bpb
        check_condition(bpb.ls_per_clus > 0, "invalid bpb value: ls_per_clus")
        check_condition(bpb.bytes_per_ls > 0, "invalid bpb value: bytes_per_ls")

        self.fat12 = False
        self.fat32 = self.data.boot_sector.is_fat32
        if not self.fat32:
            self.fat12 = self.is_fat12()

        self.pos_data = self.data.boot_sector.pos_root_dir + self.data.boot_sector.size_root_dir
        check_condition(self.pos_data <= self.infile.size,
                "data sector outside file")

        for record in self.data.root_dir.records:
            # TODO: check whether or not file names are correct
            pass

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

    def unpack(self, meta_directory):
        return self.unpack_directory(meta_directory, self.data.root_dir.records, pathlib.Path('.'))
        #try:
            #return self.unpack_directory(meta_directory, self.data.root_dir.records)
        #except BaseException as e:
            #raise UnpackParserException(e.args)

    def unpack_directory(self, meta_directory, directory_records, prefix):
        lfn = False
        fn = ''
        for record in directory_records:
            log.debug(f'vfat_parser: {record=} {record.attributes=}')
            # log.debug(f'{get_lfn_part(record)=!r} {get_short_filename(record)=!r} {record.start_clus=} {record.file_size=}')
            if not lfn:
                if record.attributes == 0x0f: # is lfn_entry
                    lfn = True
                    fn = get_lfn_part(record)
                else:
                    fn = get_short_filename(record)
            else: # lfn
                if record.attributes == 0x0f:

                    fn = get_lfn_part(record) + fn

                else:
                    lfn = False
                    pass # keep long filename
            log.debug(f'vfat_parser: {fn=} {lfn=}')
            if not lfn:
                if fn[0] == '\0':
                    continue
                log.debug(f'vfat_parser: {record.attr_subdirectory=}')
                # get other attributes
                if record.attr_subdirectory:
                    if fn not in ['.', '..']:
                        log.debug('vfat:unpack_directory: get dir_entries')
                        dir_entries = self.get_dir_entries(record.start_clus)
                        # We are just extracting the directory, not creating a
                        # MetaDirectory for it.
                        log.debug(f'vfat:unpack_directory: {dir_entries=}')
                        log.debug(f'vfat:unpack_directory: {prefix!r} / {fn!r}')
                        meta_directory.unpack_directory(prefix / fn)
                        # parse dir_entries for subdir
                        subdir = vfat_directory.VfatDirectory.from_bytes(dir_entries)
                        for unpacked_md in self.unpack_directory(meta_directory,
                                subdir.records, prefix / fn):
                            yield unpacked_md
                elif record.attr_volume_label:
                    pass
                else:
                    for unpacked_md in self.extract_file(meta_directory, record.start_clus, record.file_size, prefix / fn):
                        yield unpacked_md

    def get_dir_entries(self, start_cluster):
        dir_entries = b''
        cluster_size = self.data.boot_sector.bpb.ls_per_clus * \
                self.data.boot_sector.bpb.bytes_per_ls
        for cluster in self.cluster_chain(start_cluster):
            start = self.pos_data + (cluster-2) * cluster_size
            check_condition(start+cluster_size <= self.infile.size,
                    "file data outside file")
            self.infile.seek(start)
            dir_entries += self.infile.read(cluster_size)
        return dir_entries

    def extract_file(self, meta_directory, start_cluster, file_size, out_fn):
        size_read = 0
        cluster_size = self.data.boot_sector.bpb.ls_per_clus * \
                self.data.boot_sector.bpb.bytes_per_ls
        with meta_directory.unpack_regular_file(pathlib.Path(out_fn)) as (unpacked_md, f):
            for cluster in self.cluster_chain(start_cluster):
                bytes_to_read = min(cluster_size, file_size - size_read)
                start = self.pos_data + (cluster-2) * cluster_size
                check_condition(start+bytes_to_read <= self.infile.size,
                        "file data outside file")

                os.sendfile(f.fileno(), self.infile.fileno(), start + self.infile.offset, bytes_to_read)
                size_read += bytes_to_read
            yield unpacked_md

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

    labels = ['filesystem','vfat']

    @property
    def metadata(self):
        metadata = {}
        # store the OEM name. Even though the OEM name should be padded
        # with spaces sometimes there are NUL characters instead
        oem_name = self.data.boot_sector.oem_name.split('\x00')[0]

        metadata['oem'] = oem_name
        return metadata
