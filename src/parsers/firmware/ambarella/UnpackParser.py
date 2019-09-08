
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_ambarella

class AmbarellaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x818, b'\x90\xeb\x24\xa3')
    ]
    pretty_name = 'ambarella'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ambarella(fileresult, scan_environment, offset, unpack_dir)

