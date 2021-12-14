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
from . import mbr_partition_table
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from FileResult import FileResult

class MbrPartitionTableUnpackParser(UnpackParser):
    pretty_name = 'mbr'
    signatures = [
            (0x1be + 4*(1+3+1+3+4+4), b'\x55\xaa')
    ]

    def parse(self):
        raise UnpackParserException('disabled')
        try:
            self.data = mbr_partition_table.MbrPartitionTable.from_io(self.infile)
            for p in self.data.partitions:
                check_condition(not (p.lba_start == 0 and p.num_sectors != 0),
                                'invalid LBA/sectors')
                check_condition((p.lba_start + p.num_sectors) * 512 <= self.fileresult.filesize,
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

    def unpack(self):
        """extract any files from the input file"""
        unpacked_files = []
        partition_number = 0
        for p in self.data.partitions:
            partition_ext = "part"
            partition_start = p.lba_start * 512
            partition_length = p.num_sectors * 512
            outfile_rel = self.rel_unpack_dir / ("unpacked.mbr-partition%d.%s" %
                (partition_number, partition_ext))
            self.extract_to_file(outfile_rel, 
                    partition_start, partition_length)
            partition_name = p.partition_type.name
            # TODO: add partition name to labels
            outlabels = ['partition']
            fr = FileResult(self.fileresult, outfile_rel, set(outlabels))
            unpacked_files.append( fr )
            partition_number += 1
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        self.unpack_results.set_labels(['filesystem','mbr'])
        self.unpack_results.set_metadata({})
