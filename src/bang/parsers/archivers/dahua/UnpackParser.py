
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_dahua

class DahuaUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'DH\x03\04')
    ]
    pretty_name = 'dahua'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dahua(fileresult, scan_environment, offset, unpack_dir)

