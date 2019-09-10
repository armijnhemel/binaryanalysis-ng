
import os
from UnpackParser import WrappedUnpackParser
from bangtext import unpack_ihex

class IhexUnpackParser(WrappedUnpackParser):
    extensions = ['.hex', '.ihex']
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'ihex'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ihex(fileresult, scan_environment, offset, unpack_dir)

