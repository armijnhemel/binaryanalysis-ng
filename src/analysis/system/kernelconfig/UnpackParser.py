
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_kernel_config

class KernelConfigUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
    ]
    scan_if_featureless = True
    pretty_name = 'kernelconfig'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_kernel_config(fileresult, scan_environment, offset, unpack_dir)

