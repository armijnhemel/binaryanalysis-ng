
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_cramfs

class CramfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x45\x3d\xcd\x28'),
        (0, b'\x28\xcd\x3d\x45')
    ]
    pretty_name = 'cramfs'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_cramfs(fileresult, scan_environment, offset, unpack_dir)

