
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_ubi

class UbiUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0,  b'UBI#')
    ]
    pretty_name = 'ubi'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ubi(fileresult, scan_environment, offset, unpack_dir)

