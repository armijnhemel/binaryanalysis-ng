
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_lzop

class LzopUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'lzop'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lzop(fileresult, scan_environment, offset, unpack_dir)

