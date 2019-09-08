
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_zstd

class ZstdUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x28\xb5\x2f\xfd')
    ]
    pretty_name = 'zstd'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zstd(fileresult, scan_environment, offset, unpack_dir)

