
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_minix1l

class Minix1lUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0x410, b'\x8f\x13')
    ]
    pretty_name = 'minix'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_minix1l(fileresult, scan_environment, offset, unpack_dir)

