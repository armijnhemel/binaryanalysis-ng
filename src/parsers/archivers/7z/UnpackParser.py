
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_7z

class SevenzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'7z\xbc\xaf\x27\x1c')
    ]
    pretty_name = '7z'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_7z(fileresult, scan_environment, offset, unpack_dir)

