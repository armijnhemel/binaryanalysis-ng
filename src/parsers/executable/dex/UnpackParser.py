
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_dex

class DexUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'dex\n')
    ]
    pretty_name = 'dex'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dex(fileresult, scan_environment, offset, unpack_dir)

