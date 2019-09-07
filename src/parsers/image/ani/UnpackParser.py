
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_ani

class AniUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'ACON')
    ]
    pretty_name = 'ani'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ani(fileresult, scan_environment, offset, unpack_dir)

