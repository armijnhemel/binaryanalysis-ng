
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_serialized_java

class SerializedJavaUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xac\xed\x00\x05')
    ]
    pretty_name = 'serialized_java'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_serialized_java(fileresult, scan_environment, offset, unpack_dir)

