
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_truetype_font

class TruetypeFontUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00\x01\x00\x00')
    ]
    pretty_name = 'truetype'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_truetype_font(fileresult, scan_environment, offset, unpack_dir)

