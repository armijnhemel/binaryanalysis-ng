
import os
from UnpackParser import UnpackParser
from banggames import unpack_quake_pak

class QuakePakUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PACK')
    ]
    pretty_name = 'quakepak'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_quake_pak(fileresult, scan_environment, offset, unpack_dir)

