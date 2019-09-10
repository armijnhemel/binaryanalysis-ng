
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_minidump

class MinidumpUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'MDMP')
    ]
    pretty_name = 'minidump'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_minidump(fileresult, scan_environment, offset, unpack_dir)

