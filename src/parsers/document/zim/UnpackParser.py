
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_zim

class ZimUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5a\x49\x4d\x04')
    ]
    pretty_name = 'zim'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zim(fileresult, scan_environment, offset, unpack_dir)

