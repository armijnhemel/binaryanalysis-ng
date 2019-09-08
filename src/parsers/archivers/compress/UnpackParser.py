
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_compress

class CompressUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1f\x9d')
    ]
    pretty_name = 'compress'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_compress(fileresult, scan_environment, offset, unpack_dir)

