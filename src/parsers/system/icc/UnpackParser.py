
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_icc

class IccUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (36, b'acsp')
    ]
    pretty_name = 'icc'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_icc(fileresult, scan_environment, offset, unpack_dir)

