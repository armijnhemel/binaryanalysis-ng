
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_odex

class OdexUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'dey\n')
    ]
    pretty_name = 'odex'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_odex(fileresult, scan_environment, offset, unpack_dir)

