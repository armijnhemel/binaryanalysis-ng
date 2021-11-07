
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_bflt

class BfltUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'bFLT')
    ]
    pretty_name = 'bflt'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bflt(fileresult, scan_environment, offset, unpack_dir)

