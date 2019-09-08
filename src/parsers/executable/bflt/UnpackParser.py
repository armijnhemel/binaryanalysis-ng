
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_blft

class BlftUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'bFLT')
    ]
    pretty_name = 'blft'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_blft(fileresult, scan_environment, offset, unpack_dir)

