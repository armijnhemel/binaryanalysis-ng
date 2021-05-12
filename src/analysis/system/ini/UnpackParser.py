
import os
from UnpackParser import WrappedUnpackParser
from bangtext import unpack_ini

class IniUnpackParser(WrappedUnpackParser):
    extensions = ['.ini']
    signatures = [
    ]
    pretty_name = 'ini'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ini(fileresult, scan_environment, offset, unpack_dir)

