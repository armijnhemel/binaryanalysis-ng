
import os
from UnpackParser import WrappedUnpackParser
from banggames import unpack_quake_pak

class QuakePakUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'PACK')
    ]
    pretty_name = 'quakepak'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_quake_pak(fileresult, scan_environment, offset, unpack_dir)

