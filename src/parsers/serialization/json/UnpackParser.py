
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_json

class JsonUnpackParser(UnpackParser):
    extensions = ['.json']
    signatures = [
    ]
    pretty_name = 'json'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_json(fileresult, scan_environment, offset, unpack_dir)

