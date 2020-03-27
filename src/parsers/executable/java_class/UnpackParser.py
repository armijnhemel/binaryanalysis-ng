
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_java_class

class JavaClassUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xba\xbe')
    ]
    pretty_name = 'javaclass'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_java_class(fileresult, scan_environment, offset, unpack_dir)

