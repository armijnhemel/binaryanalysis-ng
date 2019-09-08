
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_bzip2

class Bzip2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BZh')
    ]
    pretty_name = 'bzip2'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bzip2(fileresult, scan_environment, offset, unpack_dir)

