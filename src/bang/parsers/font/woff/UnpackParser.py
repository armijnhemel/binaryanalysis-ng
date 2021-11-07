
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_woff

class WoffUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'wOFF')
    ]
    pretty_name = 'woff'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_woff(fileresult, scan_environment, offset, unpack_dir)

