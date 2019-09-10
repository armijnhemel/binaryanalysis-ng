
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_rpm

class RpmUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xed\xab\xee\xdb')
    ]
    pretty_name = 'rpm'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_rpm(fileresult, scan_environment, offset, unpack_dir)

