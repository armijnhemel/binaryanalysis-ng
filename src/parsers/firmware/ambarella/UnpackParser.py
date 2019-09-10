
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_ambarella

class AmbarellaUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0x818, b'\x90\xeb\x24\xa3')
    ]
    pretty_name = 'ambarella'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ambarella(fileresult, scan_environment, offset, unpack_dir)

