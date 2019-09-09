
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_chrome_pak

class ChromePakUnpackParser(UnpackParser):
    extensions = ['.pak']
    signatures = []
    pretty_name = 'pak'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_chrome_pak(fileresult, scan_environment, offset, unpack_dir)

