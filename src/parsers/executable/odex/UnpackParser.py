
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_odex

class OdexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'dey\n')
    ]
    pretty_name = 'odex'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_odex(fileresult, scan_environment, offset, unpack_dir)

