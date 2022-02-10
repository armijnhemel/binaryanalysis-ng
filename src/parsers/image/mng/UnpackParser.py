
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_mng

class MngUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x8aMNG\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'mng'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_mng(fileresult, scan_environment, offset, unpack_dir)

