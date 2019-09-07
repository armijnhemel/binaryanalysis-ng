
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_ktx11

class Ktx11UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xabKTX 11\xbb\r\n\x1a\n')
    ]
    pretty_name = 'ktx'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ktx11(fileresult, scan_environment, offset, unpack_dir)

