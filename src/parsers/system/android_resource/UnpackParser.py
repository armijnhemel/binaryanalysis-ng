
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_resource

class AndroidResourceUnpackParser(UnpackParser):
    extensions = ['resources.arsc']
    signatures = [
        (0, b'\x03\x00\x08\x00')
    ]
    pretty_name = 'androidresource'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_resource(fileresult, scan_environment, offset, unpack_dir)

