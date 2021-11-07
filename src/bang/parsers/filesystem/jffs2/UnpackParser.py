
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_jffs2

class Jffs2UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x85\x19'),
        (0, b'\x19\x85')
    ]
    pretty_name = 'jffs2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_jffs2(fileresult, scan_environment, offset, unpack_dir)

