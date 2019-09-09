
import os
from UnpackParser import UnpackParser
from bangtext import unpack_script

class IhexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'script'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_script(fileresult, scan_environment, offset, unpack_dir)

