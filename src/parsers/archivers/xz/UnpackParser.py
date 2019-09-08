
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_xz

class XzUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xfd\x37\x7a\x58\x5a\x00')
    ]
    pretty_name = 'xz'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_xz(fileresult, scan_environment, offset, unpack_dir)

