
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_certificate

class CertificateUnpackParser(WrappedUnpackParser):
    extensions = ['.rsa', '.pem']
    signatures = [
        (0, b'-----BEGIN ')
    ]
    pretty_name = 'certificate'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_certificate(fileresult, scan_environment, offset, unpack_dir)

