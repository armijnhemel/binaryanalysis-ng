
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_lzip

class LzipUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'LZIP')
    ]
    pretty_name = 'lzip'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lzip(fileresult, scan_environment, offset, unpack_dir)

