
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_appledouble

class AppledoubleUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00\x05\x16\x07')
    ]
    pretty_name = 'appledouble'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_appledouble(fileresult, scan_environment, offset, unpack_dir)

