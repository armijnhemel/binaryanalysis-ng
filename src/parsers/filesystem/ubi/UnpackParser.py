
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_ubi

class UbiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0,  b'UBI#')
    ]
    pretty_name = 'ubi'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ubi(fileresult, scan_environment, offset, unpack_dir)

