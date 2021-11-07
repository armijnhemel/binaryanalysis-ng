
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_7z

class SevenzipUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'7z\xbc\xaf\x27\x1c')
    ]
    pretty_name = '7z'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_7z(fileresult, scan_environment, offset, unpack_dir)

