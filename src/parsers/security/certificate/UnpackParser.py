
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_certificate

class CertificateUnpackParser(UnpackParser):
    extensions = ['.rsa', '.pem']
    signatures = [
        (0, b'-----BEGIN ')
    ]
    pretty_name = 'certificate'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_certificate(fileresult, scan_environment, offset, unpack_dir)

