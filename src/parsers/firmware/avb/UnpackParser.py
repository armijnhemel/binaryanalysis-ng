
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_avb

class AvbUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'AVB0')
    ]
    pretty_name = 'avb'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_avb(fileresult, scan_environment, offset, unpack_dir)

