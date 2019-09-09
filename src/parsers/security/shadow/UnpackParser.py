
import os
from UnpackParser import UnpackParser
from bangtext import unpack_shadow

class ShadowUnpackParser(UnpackParser):
    extensions = ['shadow']
    signatures = [
    ]
    pretty_name = 'shadow'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_shadow(fileresult, scan_environment, offset, unpack_dir)

