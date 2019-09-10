
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_lzma

class LzmaUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x5d\x00\x00'),
        (0, b'\x6d\x00\x00'),
        (0, b'\x6c\x00\x00')
    ]
    pretty_name = 'lzma'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lzma(fileresult, scan_environment, offset, unpack_dir)

