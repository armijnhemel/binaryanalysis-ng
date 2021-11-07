
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_icc

class IccUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (36, b'acsp')
    ]
    pretty_name = 'icc'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_icc(fileresult, scan_environment, offset, unpack_dir)

