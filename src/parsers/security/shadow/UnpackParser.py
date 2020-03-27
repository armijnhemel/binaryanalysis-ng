
import os
from UnpackParser import WrappedUnpackParser
from bangtext import unpack_shadow

class ShadowUnpackParser(WrappedUnpackParser):
    extensions = ['shadow']
    signatures = [
    ]
    pretty_name = 'shadow'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_shadow(fileresult, scan_environment, offset, unpack_dir)

