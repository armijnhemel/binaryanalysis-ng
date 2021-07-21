
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_script

class ScriptUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'script'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_script(fileresult, scan_environment, offset, unpack_dir)

