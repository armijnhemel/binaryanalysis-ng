
import os
from UnpackParser import UnpackParser
from bangtext import unpack_kernel_config

class KernelConfigUnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    pretty_name = 'kernelconfig'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_kernel_config(fileresult, scan_environment, offset, unpack_dir)

