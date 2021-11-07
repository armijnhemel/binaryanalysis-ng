
import os
from bang.UnpackParser import WrappedUnpackParser
from bangmedia import unpack_aiff

class AiffUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'FORM')
    ]
    pretty_name = 'aiff'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_aiff(fileresult, scan_environment, offset, unpack_dir)

