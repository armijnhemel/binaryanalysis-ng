
import os
from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_plf

class PlfUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'PLF!')
    ]
    pretty_name = 'plf'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_plf(fileresult, scan_environment, offset, unpack_dir)

