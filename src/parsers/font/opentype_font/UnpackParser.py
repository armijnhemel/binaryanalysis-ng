
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_opentype_font

class OpentypeFontUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'OTTO')
    ]
    pretty_name = 'opentype'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_opentype_font(fileresult, scan_environment, offset, unpack_dir)

