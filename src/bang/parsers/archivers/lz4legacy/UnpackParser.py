
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_lz4legacy

class Lz4legacyUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x02\x21\x4c\x18')
    ]
    pretty_name = 'lz4_legacy'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lz4legacy(fileresult, scan_environment, offset, unpack_dir)

