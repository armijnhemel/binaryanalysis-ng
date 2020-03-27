
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_chrome_pak

class ChromePakUnpackParser(WrappedUnpackParser):
    extensions = ['.pak']
    signatures = []
    pretty_name = 'pak'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_chrome_pak(fileresult, scan_environment, offset, unpack_dir)

