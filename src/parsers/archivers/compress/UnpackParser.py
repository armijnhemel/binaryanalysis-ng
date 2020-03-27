
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_compress

class CompressUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1f\x9d')
    ]
    pretty_name = 'compress'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_compress(fileresult, scan_environment, offset, unpack_dir)

