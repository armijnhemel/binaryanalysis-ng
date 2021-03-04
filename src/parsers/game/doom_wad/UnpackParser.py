import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import doom_wad

class DoomWadUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'IWAD')
    ]
    pretty_name = 'doomwad'

    # http://web.archive.org/web/20090530112359/http://www.gamers.org/dhs/helpdocs/dmsp1666.html
    # chapter 2
    def parse(self):
        print(self.infile.tell())
        try:
            self.data = doom_wad.DoomWad.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            print(e)
            raise UnpackParserException(e.args)
        check_condition(self.data.num_index_entries > 0, "no lumps defined")

    def calculate_unpacked_size(self):
        print(self.offset, self.data.index_offset)
        self.unpacked_size = self.data.index_offset + self.data.num_index_entries * 16
        for i in self.data.index:
            self.unpacked_size = max(self.unpacked_size, i.offset + i.size)
        print(self.unpacked_size)

    def set_metadata_and_labels(self):
        self.unpack_results['labels'] = ['doom', 'wad', 'resource']
        self.unpack_results['metadata'] = {}
