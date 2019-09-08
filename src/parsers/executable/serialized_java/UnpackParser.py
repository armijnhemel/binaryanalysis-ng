
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_serialized_java

class SerializedJavaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xac\xed\x00\x05')
    ]
    pretty_name = 'serialized_java'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_serialized_java(fileresult, scan_environment, offset, unpack_dir)

