
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_chm

class ChmUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ITSF\x03\x00\x00\x00')
    ]
    pretty_name = 'chm'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_chm(fileresult, scan_environment, offset, unpack_dir)

