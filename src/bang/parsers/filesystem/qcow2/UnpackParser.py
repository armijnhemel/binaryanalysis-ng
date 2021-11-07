
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_qcow2

class Qcow2UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'QFI\xfb')
    ]
    pretty_name = 'qcow2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_qcow2(fileresult, scan_environment, offset, unpack_dir)

