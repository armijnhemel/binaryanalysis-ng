
import os
from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_yaffs2

class Yaffs2UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff'),
        (0, b'\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff'),
        (0, b'\x00\x00\x00\x03\x00\x00\x00\x01\xff\xff'),
        (0, b'\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff')
    ]
    pretty_name = 'yaffs2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_yaffs2(fileresult, scan_environment, offset, unpack_dir)

