
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_zstd

class ZstdUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x28\xb5\x2f\xfd')
    ]
    pretty_name = 'zstd'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zstd(fileresult, scan_environment, offset, unpack_dir)

