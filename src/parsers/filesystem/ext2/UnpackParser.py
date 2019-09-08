
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_ext2

class Ext2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x438,  b'\x53\xef')
    ]
    pretty_name = 'ext2'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ext2(fileresult, scan_environment, offset, unpack_dir)

