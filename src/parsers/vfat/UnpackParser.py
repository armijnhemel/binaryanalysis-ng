import os
import struct
from . import vfat
from UnpackParser import UnpackParser

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
    return fn.lower()

class VfatUnpackParser(UnpackParser):
    pretty_name = 'fat'
    signatures = [
            ]

    def parse(self):
        self.data = vfat.Vfat.from_io(self.infile)
        self.fat12 = self.is_fat12()
        self.fat32 = self.data.boot_sector.is_fat32
        self.pos_data = self.data.boot_sector.pos_root_dir + self.data.boot_sector.size_root_dir

    def calculate_unpacked_size(self, offset):
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

    def unpack(self, fileresult, scan_environment, offset, rel_unpack_dir):
        out_dir_rel = '.'
        self.unpack_directory(self.data.root_dir.records, out_dir_rel)

    def unpack_directory(self, directory_records, out_dir_rel):
        lfn = False
        fn = ''
        for record in directory_records:
            # print('->', record.is_lfn_entry, fn)
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
                if fn[0] == 0: continue
                # get other attributes
                print('fn', repr(fn))
                # TODO: if normal_file
                self.extract_file(record.start_clus, record.file_size)
                # if directory

    def extract_file(self, start_cluster, file_size):
        # TODO: parameter out_file_rel
        # print('clus', start_cluster)
        # print('size',file_size)
        cluster = start_cluster
        size_read = 0
        cluster_size = self.data.boot_sector.bpb.ls_per_clus * \
                self.data.boot_sector.bpb.bytes_per_ls
        while not self.is_end_cluster(cluster):
            print('lookup cluster', cluster)
            print('read bytes', min(cluster_size, file_size - size_read))
            # TODO: find data in file, copy data to outfile
            bytes_to_read = min(cluster_size, file_size - size_read)

            self.infile.seek(self.pos_data + (cluster-2) * cluster_size)
            bs = self.infile.read(bytes_to_read)
            print(repr(bs))
            # TODO: use os.sendfile to copy the cluster bytes to the outfile

            size_read += bytes_to_read
            cluster = self.get_cluster_map_entry(cluster)

    def is_end_cluster(self, cluster):
        if self.fat12:
            return cluster >= 0xff8
        if self.fat32:
            return (cluster & 0xffffff8) == 0xffffff8
        return cluster >= 0xfff8

    def get_cluster_map_entry(self, cluster):
        if self.fat12:
            return self.get_fat12_entry(cluster)
        if self.fat32:
            return self.get_fat32_entry(cluster)
        return self.get_fat16_entry(cluster)

