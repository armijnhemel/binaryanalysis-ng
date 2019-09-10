
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_device_tree

class DeviceTreeUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xd0\x0d\xfe\xed')
    ]
    pretty_name = 'dtb'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_device_tree(fileresult, scan_environment, offset, unpack_dir)

