
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_lz4

class Lz4UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x04\x22\x4d\x18')
    ]
    pretty_name = 'lz4'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lz4(fileresult, scan_environment, offset, unpack_dir)

