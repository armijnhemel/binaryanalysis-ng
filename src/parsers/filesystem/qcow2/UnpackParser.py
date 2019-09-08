
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_qcow2

class Qcow2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QFI\xfb')
    ]
    pretty_name = 'qcow2'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_qcow2(fileresult, scan_environment, offset, unpack_dir)

