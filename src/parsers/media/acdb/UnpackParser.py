
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_acdb

class AcdbUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QCMSNDDB')
    ]
    pretty_name = 'acdb'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_acdb(fileresult, scan_environment, offset, unpack_dir)

