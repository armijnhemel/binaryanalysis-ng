
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_css

class CssUnpackParser(WrappedUnpackParser):
    extensions = [ '.css' ]
    signatures = [ ]
    pretty_name = 'css'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_css(fileresult, scan_environment, offset, unpack_dir)

