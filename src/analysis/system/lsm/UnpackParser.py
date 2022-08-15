
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_lsm

class LsmUnpackParser(WrappedUnpackParser):
    extensions = ['.lsm']
    signatures = [
    ]
    pretty_name = 'lsm'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lsm(fileresult, scan_environment, offset, unpack_dir)

