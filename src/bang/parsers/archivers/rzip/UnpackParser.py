
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_rzip

class RzipUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'RZIP')
    ]
    pretty_name = 'rzip'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_rzip(fileresult, scan_environment, offset, unpack_dir)

