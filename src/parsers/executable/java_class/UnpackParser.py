
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_java_class

class JavaClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xba\xbe')
    ]
    pretty_name = 'javaclass'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_java_class(fileresult, scan_environment, offset, unpack_dir)

