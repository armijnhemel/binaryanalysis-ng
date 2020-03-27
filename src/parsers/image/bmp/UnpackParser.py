
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_bmp

class BmpUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'BM')
    ]
    pretty_name = 'bmp'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bmp(fileresult, scan_environment, offset, unpack_dir)

