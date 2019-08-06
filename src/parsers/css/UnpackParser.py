
import os
from UnpackParser import UnpackParser
from bangtext import unpack_css

class CssUnpackParser(UnpackParser):
    extensions = [ '.css' ]
    signatures = [ ]
    pretty_name = 'css'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_css(fileresult, scan_environment, offset, unpack_dir)

