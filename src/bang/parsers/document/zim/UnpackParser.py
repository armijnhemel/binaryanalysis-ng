
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_zim

class ZimUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5a\x49\x4d\x04')
    ]
    pretty_name = 'zim'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zim(fileresult, scan_environment, offset, unpack_dir)

