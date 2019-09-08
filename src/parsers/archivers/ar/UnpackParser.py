
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_ar

class ArUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'!<arch>')
    ]
    pretty_name = 'ar'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ar(fileresult, scan_environment, offset, unpack_dir)

