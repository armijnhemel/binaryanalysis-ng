
import os
from UnpackParser import UnpackParser
from bangtext import unpack_srec

class SrecUnpackParser(UnpackParser):
    extensions = ['.srec']
    signatures = [
    ]
    pretty_name = 'srec'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_srec(fileresult, scan_environment, offset, unpack_dir)

