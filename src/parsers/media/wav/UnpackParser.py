
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_wav

class WavUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'WAVE')
    ]
    pretty_name = 'wav'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_wav(fileresult, scan_environment, offset, unpack_dir)

