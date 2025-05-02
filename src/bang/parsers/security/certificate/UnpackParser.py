# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

# The SSL certificate formats themselves are defined in for example:
# * X.690 - https://en.wikipedia.org/wiki/X.690
# * X.509 - https://en.wikipedia.org/wiki/X.509

import os
import pathlib
import shutil
import string
import subprocess

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class CertificateUnpackParser(UnpackParser):
    #extensions = ['.rsa', '.pem', '.der']
    extensions = []
    signatures = [
        (0, b'-----BEGIN ')
    ]
    pretty_name = 'certificate'

    def extract_certificate(self, cert):
        labels = []

        # First see if a file is in DER format # TODO binary .der files
        p = subprocess.Popen(["openssl", "asn1parse", "-inform", "DER"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate(cert)
        if p.returncode == 0:
            labels.append('der')
            return(True, labels)

        # then check if it is a PEM
        p = subprocess.Popen(["openssl", "asn1parse", "-inform", "PEM"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate(cert)
        if p.returncode == 0:
            # there could be several certificates or keys
            # inside the file.
            # TODO: split into certificates and private keys
            # The openssl program also accepts binary crap,
            # so add some extra checks.
            try:
                for checkline in cert.splitlines():
                    line = checkline.decode()
                    # then check if this is perhaps a private key
                    if "PRIVATE KEY" in line:
                        labels.append('private key')
                    # or a certificate
                    if "BEGIN CERTIFICATE" in line:
                        labels.append("certificate")
                    # or a trusted certificate
                    if "TRUSTED CERTIFICATE" in line:
                        labels.append("trusted certificate")
            except UnicodeDecodeError:
                return(False, labels)

            return(True, labels)

        return(False, labels)

    def parse(self):
        # For reasons unknown pyOpenSSL sometimes barfs on certs from
        # Android, so use an external tool (for now).
        check_condition(shutil.which('openssl') is not None,
                        "openssl program not found")

        buf = self.infile.read(80)
        self.certtype = None
        if b'PRIVATE KEY' in buf:
            self.certtype = 'key'
        elif b'CERTIFICATE' in buf:
            self.certtype = 'certificate'

        # try to find the end of the certificate
        end_pos = -1
        self.infile.seek(0)
        self.pos = self.infile.tell()
        cert_unpacked = False

        while True:
            buf = self.infile.read(2048)
            if buf == b'':
                break
            end_pos = buf.find(b'-----END')

            if end_pos != -1:
                if self.certtype == 'key':
                    end_res = buf.find(b'KEY-----', end_pos)
                    if end_res != -1:
                        end_of_certificate = self.pos + end_res + 8
                        cert_unpacked = True
                elif self.certtype == 'certificate':
                    end_res = buf.find(b'CERTIFICATE-----', end_pos)
                    if end_res != -1:
                        end_of_certificate = self.pos + end_res + 16
                        cert_unpacked = True
                else:
                    end_res = buf.find(b'-----', end_pos + 1)
                    if end_res != -1:
                        end_of_certificate = self.pos + end_res + 5
                        cert_unpacked = True
                break

            # make sure there is a little bit of overlap
            if self.infile.tell() == self.infile.size:
                break
            self.infile.seek(-15, os.SEEK_CUR)
            self.pos = self.infile.tell()

        check_condition(end_pos != -1, "no end of certificate found")
        check_condition(cert_unpacked, "no certificate found")

        # extra sanity check for ca-certificates.crt to prevent
        # writing many 1 byte files with whitespace that clutter
        # the scan results.
        if pathlib.Path(self.infile.name).name == 'ca-certificates.crt':
            self.infile.seek(end_of_certificate)
            if self.infile.read(1) == b'\n':
                end_of_certificate += 1
        else:
            # check if there is an extra newline at the end
            if self.infile.size - end_of_certificate == 1:
                self.infile.seek(end_of_certificate)
                if self.infile.read(1) == b'\n':
                    end_of_certificate += 1

        # check the certificate
        self.infile.seek(0)
        cert = self.infile.read(end_of_certificate)
        check_condition(list(filter(lambda x: chr(x) not in string.printable, cert)) == [],
                        "text cert can only contain ASCII printable characters")
        (res, self.cert_labels) = self.extract_certificate(cert)
        check_condition(res, "not a valid certificate")

    @property
    def labels(self):
        labels = ['certificate']
        labels += self.cert_labels
        return labels

    metadata = {}
