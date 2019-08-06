
import os
from . import cpio_new_ascii
from UnpackParser import UnpackParser

class CpioUnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    pretty_name = 'cpio'

    def parse(self):
        self.data = cpio_new_ascii.CpioNewAscii.from_io(self.infile)
    def calculate_unpacked_size(self, offset):
        self.unpacked_size = self.infile.tell() - offset
        # self.unpacked_size = 
        # for e in self.data.entries:
        #    print(e)
        #    print(dir(e))
        #    print(e.header)
    def unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return []
    def set_metadata_and_labels(self):
        return


