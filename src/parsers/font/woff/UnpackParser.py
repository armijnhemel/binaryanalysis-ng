
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_woff

class WoffUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'wOFF')
    ]
    pretty_name = 'woff'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_woff(fileresult, scan_environment, offset, unpack_dir)

