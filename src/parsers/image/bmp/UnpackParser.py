
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_bmp

class BmpUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BM')
    ]
    pretty_name = 'bmp'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bmp(fileresult, scan_environment, offset, unpack_dir)

