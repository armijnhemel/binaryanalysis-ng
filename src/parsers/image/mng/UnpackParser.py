
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_mng

class MngUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x8aMNG\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'mng'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_mng(fileresult, scan_environment, offset, unpack_dir)

