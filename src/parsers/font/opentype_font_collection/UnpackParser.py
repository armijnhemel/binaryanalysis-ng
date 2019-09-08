
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_opentype_font_collection

class OpentypeFontCollectionUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ttcf')
    ]
    pretty_name = 'ttc'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_opentype_font_collection(fileresult, scan_environment, offset, unpack_dir)

