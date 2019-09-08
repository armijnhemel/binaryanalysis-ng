
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_appledouble

class GzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00\x05\x16\x07')
    ]
    pretty_name = 'appledouble'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_appledouble(fileresult, scan_environment, offset, unpack_dir)

