
import os
from UnpackParser import UnpackParser
from bangtext import unpack_pkg_config

class PkgConfigUnpackParser(UnpackParser):
    extensions = ['.pc']
    signatures = [
    ]
    pretty_name = 'pc'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pkg_config(fileresult, scan_environment, offset, unpack_dir)

