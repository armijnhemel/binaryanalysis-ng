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
import pathlib
from . import mbr_partition_table
from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException

class MbrPartitionTableUnpackParser(UnpackParser):
    pretty_name = 'mbr'
    signatures = [
            (0x1be + 4*(1+3+1+3+4+4), b'\x55\xaa')
    ]

    def parse(self):
        # raise UnpackParserException('disabled')
        try:
            self.data = mbr_partition_table.MbrPartitionTable.from_io(self.infile)
            for p in self.data.partitions:
                check_condition(not (p.lba_start == 0 and p.num_sectors != 0),
                                'invalid LBA/sectors')
                check_condition((p.lba_start + p.num_sectors) * 512 <= self.infile.size,
                                "partition bigger than file")
        except BaseException as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = 0
        try:
            for p in self.data.partitions:
                self.unpacked_size = max( self.unpacked_size,
                        (p.lba_start + p.num_sectors) * 512 )
        except BaseException as e:
            raise UnpackParserException(e.args)
        check_condition(self.unpacked_size >= 0x1be,
                "invalid partition table: no partitions")

    def unpack(self, meta_directory):
        """extract any files from the input file"""
        unpacked_files = []
        partition_number = 0
        for p in self.data.partitions:
            partition_ext = "part"
            partition_start = p.lba_start * 512
            partition_length = p.num_sectors * 512

            outfile = "unpacked.mbr-partition%d.%s" % (partition_number, partition_ext)
            with meta_directory.unpack_regular_file(pathlib.Path(outfile)) as (unpacked_md, f):
                os.sendfile(f.fileno(), self.infile.fileno(), partition_start, partition_length)
                partition_name = p.partition_type.name
                # add some context to the MetaDirectory of the unpacked file
                # TODO: add partition name to labels
                with unpacked_md.open(open_file=False):
                    unpacked_md.info.setdefault('labels', []).append('partition')
                yield unpacked_md
            partition_number += 1

    labels = ['filesystem','mbr']
    metadata = {}

