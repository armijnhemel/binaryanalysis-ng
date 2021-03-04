import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import doom_wad

from UnpackParser import WrappedUnpackParser
from banggames import unpack_doom_wad

#class DoomWadUnpackParser(UnpackParser):
class DoomWadUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'IWAD')
    ]
    pretty_name = 'doomwad'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_doom_wad(fileresult, scan_environment, offset, unpack_dir)

    # http://web.archive.org/web/20090530112359/http://www.gamers.org/dhs/helpdocs/dmsp1666.html
    # chapter 2
    def parse(self):
        try:
            self.data = doom_wad.DoomWad.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.num_index_entries > 0, "no lumps defined")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.index_offset + self.data.num_index_entries * 16
        for i in self.data.index:
            self.unpacked_size = max(self.unpacked_size, i.offset + i.size)

    def set_metadata_and_labels(self):
        self.unpack_results['labels'] = ['doom', 'wad', 'resource']
        self.unpack_results['metadata'] = {}
