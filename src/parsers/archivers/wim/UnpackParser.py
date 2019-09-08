
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_wim

class WimUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MSWIM\x00\x00\x00')
    ]
    pretty_name = 'mswim'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_wim(fileresult, scan_environment, offset, unpack_dir)

