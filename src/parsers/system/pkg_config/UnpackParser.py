
import os
from UnpackParser import WrappedUnpackParser
from bangtext import unpack_pkg_config

class PkgConfigUnpackParser(WrappedUnpackParser):
    extensions = ['.pc']
    signatures = [
    ]
    pretty_name = 'pc'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pkg_config(fileresult, scan_environment, offset, unpack_dir)

