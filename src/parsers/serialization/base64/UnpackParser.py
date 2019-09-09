
import os
from UnpackParser import UnpackParser
from bangtext import unpack_base64

class Base64UnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'base64'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_base64(fileresult, scan_environment, offset, unpack_dir)

