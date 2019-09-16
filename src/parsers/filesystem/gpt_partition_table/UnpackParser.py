import os
from . import gpt_partition_table
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

class GptPartitionTableUnpackParser(UnpackParser):
    pretty_name = 'gpt'
    signatures = [
        ( 0x200, b'\x45\x46\x49\x20\x50\x41\x52\x54' )
    ]
    def parse(self):
        try:
            self.data = gpt_partition_table.GptPartitionTable.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)
    def calculate_unpacked_size(self):
        # According to https://web.archive.org/web/20080321063028/http://technet2.microsoft.com/windowsserver/en/library/bdeda920-1f08-4683-9ffb-7b4b50df0b5a1033.mspx?mfr=true
        # the backup GPT header is at the last sector of the disk
        try:
            self.unpacked_size = (self.data.primary.backup_lba+1)*self.data.sector_size
        except Exception as e:
            raise UnpackParserException(e.args)
        check_condition(self.unpacked_size <= self.fileresult.filesize,
                "partition bigger than file")
    def unpack(self):
        files_and_labels = []
        partition_number = 0
        for e in self.data.primary.entries:
            partition_start = e.first_lba * self.data.sector_size
            partition_end = (e.last_lba + 1) * self.data.sector_size
            partition_ext = 'part'
            outfile_rel = self.rel_unpack_dir / ("unpacked.gpt-partition%d.%s" %
                    (partition_number, partition_ext))
            self.extract_to_file(outfile_rel,
                    partition_start, partition_end - partition_start)
            # TODO: add partition GUID to labels
            # print(e.guid)
            outlabels = ['partition']
            files_and_labels.append( (outfile_rel, outlabels) )
            partition_number += 1
        return files_and_labels

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        self.unpack_results.set_labels(['filesystem','gpt'])
        self.unpack_results.set_metadata({})


