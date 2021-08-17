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
import uuid
from . import gpt_partition_table
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from FileResult import FileResult

class GptPartitionTableUnpackParser(UnpackParser):
    pretty_name = 'gpt'
    signatures = [
        ( 0x200, b'\x45\x46\x49\x20\x50\x41\x52\x54' )
    ]
    def parse(self):
        try:
            self.data = gpt_partition_table.GptPartitionTable.from_io(self.infile)
            for e in self.data.primary.entries:
                partition_start = e.first_lba * self.data.sector_size
                partition_end = (e.last_lba + 1) * self.data.sector_size
        except BaseException as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        # According to https://web.archive.org/web/20080321063028/http://technet2.microsoft.com/windowsserver/en/library/bdeda920-1f08-4683-9ffb-7b4b50df0b5a1033.mspx?mfr=true
        # the backup GPT header is at the last sector of the disk
        #
        # There are situations, such as on some Android devices , where the
        # GPT partition table and the actual partitions are separate from eachother
        # and where the LBA of the backup GPT is 0.
        #
        # There are also situations where the partition table is completely
        # unreliable, for example Android devices where certain partitions have
        # been removed from the firmware update, but where the partition table
        # has not been changed.
        try:
            self.unpacked_size = (self.data.primary.backup_lba+1)*self.data.sector_size
        except BaseException as e:
            print("EXC")
            raise UnpackParserException(e.args)

        all_entries_size = self.data.primary.entries_size * self.data.primary.entries_count
        self.unpacked_size = max(self.unpacked_size, self.data.primary.entries_start * self.data.sector_size + all_entries_size)
        for e in self.data.primary.entries:
            partition_start = e.first_lba * self.data.sector_size
            partition_end = (e.last_lba + 1) * self.data.sector_size
            if partition_start  + partition_end > self.fileresult.filesize:
                continue
        check_condition(self.unpacked_size <= self.fileresult.filesize,
                "partition bigger than file")

    def unpack(self):
        unpacked_files = []
        partition_number = 0
        for e in self.data.primary.entries:
            partition_start = e.first_lba * self.data.sector_size
            if partition_start > self.fileresult.filesize:
                continue
            partition_end = (e.last_lba + 1) * self.data.sector_size
            partition_ext = 'part'
            outfile_rel = self.rel_unpack_dir / ("unpacked.gpt-partition%d.%s" %
                    (partition_number, partition_ext))
            self.extract_to_file(outfile_rel,
                    partition_start, partition_end - partition_start)
            outlabels = ['partition']
            fr = FileResult(self.fileresult, outfile_rel, set(outlabels))
            unpacked_files.append( fr )
            partition_number += 1
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['filesystem','gpt']
        metadata = {}
        metadata['partitions'] = []

        # store GUID per partition
        for e in self.data.primary.entries:
            guid = uuid.UUID(bytes=e.guid)
            metadata['partitions'].append({'uuid': guid, 'name': e.name.split('\x00')[0]})

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
