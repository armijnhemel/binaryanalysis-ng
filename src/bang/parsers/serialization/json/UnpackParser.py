
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_json

class JsonUnpackParser(WrappedUnpackParser):
    extensions = ['.json']
    signatures = [
    ]
    pretty_name = 'json'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_json(fileresult, scan_environment, offset, unpack_dir)

