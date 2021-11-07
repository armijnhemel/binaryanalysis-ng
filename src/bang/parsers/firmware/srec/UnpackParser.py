
import os
from bang.UnpackParser import WrappedUnpackParser
from bangtext import unpack_srec

class SrecUnpackParser(WrappedUnpackParser):
    extensions = ['.srec']
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'srec'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_srec(fileresult, scan_environment, offset, unpack_dir)

