
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_device_tree

class DeviceTreeUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xd0\x0d\xfe\xed')
    ]
    pretty_name = 'dtb'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_device_tree(fileresult, scan_environment, offset, unpack_dir)

