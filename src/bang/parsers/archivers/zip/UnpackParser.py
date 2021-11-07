
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_zip

class ZipUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x50\x4b\x03\04')
    ]
    pretty_name = 'zip'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zip(fileresult, scan_environment, offset, unpack_dir)

