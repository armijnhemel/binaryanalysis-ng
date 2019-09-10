
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_wav

class WavUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (8, b'WAVE')
    ]
    pretty_name = 'wav'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_wav(fileresult, scan_environment, offset, unpack_dir)

