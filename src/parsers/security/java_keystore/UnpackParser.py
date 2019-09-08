
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_java_keystore

class JavaKeystoreUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xfe\xed\xfe\xed')
    ]
    pretty_name = 'javakeystore'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_java_keystore(fileresult, scan_environment, offset, unpack_dir)

