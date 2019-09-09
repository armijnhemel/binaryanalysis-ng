
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_sparse

class AndroidSparseUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3a\xff\x26\xed')
    ]
    pretty_name = 'androidsparse'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_sparse(fileresult, scan_environment, offset, unpack_dir)

