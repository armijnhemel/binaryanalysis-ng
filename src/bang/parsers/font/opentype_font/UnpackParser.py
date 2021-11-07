
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_opentype_font

class OpentypeFontUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'OTTO')
    ]
    pretty_name = 'opentype'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_opentype_font(fileresult, scan_environment, offset, unpack_dir)

