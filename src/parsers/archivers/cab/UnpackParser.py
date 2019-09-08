
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_cab

class CabUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MSCF\x00\x00\x00\x00')
    ]
    pretty_name = 'cab'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_cab(fileresult, scan_environment, offset, unpack_dir)

