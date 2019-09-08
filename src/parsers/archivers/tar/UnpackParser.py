
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_tar

class TarUnpackParser(UnpackParser):
    extensions = ['.tar']
    signatures = [
        (0x101, b'ustar\x00'),
        (0x101, b'ustar\x20\x20\x00')
    ]
    pretty_name = 'tar'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_tar(fileresult, scan_environment, offset, unpack_dir)

