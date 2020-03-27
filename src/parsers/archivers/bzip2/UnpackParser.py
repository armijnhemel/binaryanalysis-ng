
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_bzip2

class Bzip2UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'BZh')
    ]
    pretty_name = 'bzip2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bzip2(fileresult, scan_environment, offset, unpack_dir)

