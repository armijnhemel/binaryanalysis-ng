
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_ar

class ArUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'!<arch>')
    ]
    pretty_name = 'ar'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ar(fileresult, scan_environment, offset, unpack_dir)

