
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_nb0

class Nb0UnpackParser(WrappedUnpackParser):
    extensions = ['.nb0']
    signatures = []
    pretty_name = 'nb0'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_nb0(fileresult, scan_environment, offset, unpack_dir)

