
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_opentype_font_collection

class OpentypeFontCollectionUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'ttcf')
    ]
    pretty_name = 'ttc'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_opentype_font_collection(fileresult, scan_environment, offset, unpack_dir)

