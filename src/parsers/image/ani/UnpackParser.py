
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_ani

class AniUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (8, b'ACON')
    ]
    pretty_name = 'ani'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ani(fileresult, scan_environment, offset, unpack_dir)

