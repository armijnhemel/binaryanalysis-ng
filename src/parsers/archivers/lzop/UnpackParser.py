
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_lzop

class LzopUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'lzop'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lzop(fileresult, scan_environment, offset, unpack_dir)

