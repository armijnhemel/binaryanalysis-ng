
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_resource

class AndroidResourceUnpackParser(WrappedUnpackParser):
    extensions = ['resources.arsc']
    signatures = [
        (0, b'\x03\x00\x08\x00')
    ]
    pretty_name = 'androidresource'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_resource(fileresult, scan_environment, offset, unpack_dir)

