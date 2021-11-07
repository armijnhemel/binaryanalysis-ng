
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_java_keystore

class JavaKeystoreUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xfe\xed\xfe\xed')
    ]
    pretty_name = 'javakeystore'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_java_keystore(fileresult, scan_environment, offset, unpack_dir)

