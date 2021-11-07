
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_ext2

class Ext2UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0x438,  b'\x53\xef')
    ]
    pretty_name = 'ext2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ext2(fileresult, scan_environment, offset, unpack_dir)

