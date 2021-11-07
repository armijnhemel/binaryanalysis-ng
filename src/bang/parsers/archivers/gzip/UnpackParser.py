
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_gzip

class GzipUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1f\x8b\x08')
    ]
    pretty_name = 'gzip'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_gzip(fileresult, scan_environment, offset, unpack_dir)

