
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_crx

class CrxUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'Cr24')
    ]
    pretty_name = 'crx'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_crx(fileresult, scan_environment, offset, unpack_dir)

