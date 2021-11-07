
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_truetype_font

class TruetypeFontUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00\x01\x00\x00')
    ]
    pretty_name = 'truetype'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_truetype_font(fileresult, scan_environment, offset, unpack_dir)

