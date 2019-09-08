
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_lz4legacy

class Lz4legacyUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x02\x21\x4c\x18')
    ]
    pretty_name = 'lz4_legacy'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lz4legacy(fileresult, scan_environment, offset, unpack_dir)

