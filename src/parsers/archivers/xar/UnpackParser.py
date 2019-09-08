
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_xar

class XarUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x78\x61\x72\x21')
    ]
    pretty_name = 'xar'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_xar(fileresult, scan_environment, offset, unpack_dir)

