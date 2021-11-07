
import os
from bang.UnpackParser import WrappedUnpackParser
from bangtext import unpack_base64

class Base64UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'base64'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_base64(fileresult, scan_environment, offset, unpack_dir)

