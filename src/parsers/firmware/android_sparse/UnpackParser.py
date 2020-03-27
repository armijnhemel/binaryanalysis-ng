
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_sparse

class AndroidSparseUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3a\xff\x26\xed')
    ]
    pretty_name = 'androidsparse'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_sparse(fileresult, scan_environment, offset, unpack_dir)

