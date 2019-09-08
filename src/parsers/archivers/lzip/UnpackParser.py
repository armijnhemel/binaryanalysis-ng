
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_lzip

class LzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'LZIP')
    ]
    pretty_name = 'lzip'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lzip(fileresult, scan_environment, offset, unpack_dir)

