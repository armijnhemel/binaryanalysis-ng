# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# The SSL certificate formats themselves are defined in for example:
# * X.690 - https://en.wikipedia.org/wiki/X.690
# * X.509 - https://en.wikipedia.org/wiki/X.509

import os
import pathlib
import shutil
import string
import subprocess

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

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
            if self.infile.tell() + self.offset == self.fileresult.filesize:
                break
            self.infile.seek(-15, os.SEEK_CUR)
            self.pos = self.infile.tell()

        check_condition(end_pos != -1, "no end of certificate found")
        check_condition(cert_unpacked, "no certificate found")

        # check the certificate
        self.infile.seek(0)
        cert = self.infile.read(end_of_certificate)
        check_condition(list(filter(lambda x: chr(x) not in string.printable, cert)) == [],
                        "text cert can only contain ASCII printable characters")
        (res, self.cert_labels) = self.extract_certificate(cert)
        check_condition(res, "not a valid certificate")

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['certificate']
        metadata = {}

        labels += self.cert_labels

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
