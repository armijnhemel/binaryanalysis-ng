
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_bflt

class BfltUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'bFLT')
    ]
    pretty_name = 'bflt'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bflt(fileresult, scan_environment, offset, unpack_dir)

