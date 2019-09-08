
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_pack200

class Pack200UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xd0\x0d')
    ]
    pretty_name = 'pack200'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pack200(fileresult, scan_environment, offset, unpack_dir)

