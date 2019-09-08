
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_dahua

class DahuaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DH\x03\04')
    ]
    pretty_name = 'dahua'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dahua(fileresult, scan_environment, offset, unpack_dir)

