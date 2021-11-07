
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_acdb

class AcdbUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'QCMSNDDB')
    ]
    pretty_name = 'acdb'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_acdb(fileresult, scan_environment, offset, unpack_dir)

