
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_elf

class ElfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x7f\x45\x4c\x46')
    ]
    pretty_name = 'elf'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_elf(fileresult, scan_environment, offset, unpack_dir)

