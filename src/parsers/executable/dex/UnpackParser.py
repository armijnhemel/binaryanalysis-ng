
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_dex

class DexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'dex\n')
    ]
    pretty_name = 'dex'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dex(fileresult, scan_environment, offset, unpack_dir)

