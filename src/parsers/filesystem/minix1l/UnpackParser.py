
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_minix1l

class Minix1lUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x410, b'\x8f\x13')
    ]
    pretty_name = 'minix'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_minix1l(fileresult, scan_environment, offset, unpack_dir)

