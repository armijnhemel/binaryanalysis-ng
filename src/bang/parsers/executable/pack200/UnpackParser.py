
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_pack200

class Pack200UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xd0\x0d')
    ]
    pretty_name = 'pack200'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pack200(fileresult, scan_environment, offset, unpack_dir)

