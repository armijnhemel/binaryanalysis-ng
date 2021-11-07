
import os
from bang.UnpackParser import WrappedUnpackParser
from bangmedia import unpack_ktx11

class Ktx11UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xabKTX 11\xbb\r\n\x1a\n')
    ]
    pretty_name = 'ktx'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ktx11(fileresult, scan_environment, offset, unpack_dir)

