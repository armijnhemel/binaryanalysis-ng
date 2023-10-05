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

# https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Manifest_Specification
# https://docs.oracle.com/en/java/javase/20/docs/specs/jar/jar.html#jar-manifest

import base64
import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class JavaManifestUnpackParser(UnpackParser):
    extensions = ['manifest.mf', '.sf']
    signatures = [
    ]
    pretty_name = 'java_manifest'

    valid_attributes = set(['Name',
                            'Manifest-Version',
                            'Created-By',
                            'Signature-Version',
                            'Automatic-Module-Name',
                            'Class-Path',
                            'Multi-Release',
                            'Main-Class',
                            'Extension-List',
                            'Extension-Name',
                            'Implementation-Title',
                            'Implementation-Version',
                            'Implementation-Vendor',
                            'Implementation-Vendor-Id ',
                            'Implementation-URL',
                            'Launcher-Agent-Class',
                            'Specification-Title',
                            'Specification-Version',
                            'Specification-Vendor',
                            'Sealed',
                            'Content-Type',
                            'Java-Bean',
                            'Magic'])

    extension_attributes = ['-Extension-Name',
                            '-Specification-Version',
                            '-Implementation-Version',
                            '-Implementation-Vendor-Id',
                            '-Implementation-URL',
                            '-Digest-Manifest',
                            '-Digest-Manifest-Main-Attributes']

    custom_attributes = ['Built-By', 'Ant-Version']
    android_attributes = ['X-Android-APK-Signed']

    # https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#framework.module.bree
    bnd_attributes = ['Bnd-LastModified', 'Bundle-ActivationPolicy',
                      'Bundle-Activator', 'Bundle-Blueprint',
                      'Bundle-Category', 'Bundle-ClassPath',
                      'Bundle-ContactAddress', 'Bundle-Copyright',
                      'Bundle-Description', 'Bundle-Developers',
                      'Bundle-DocURL', 'Bundle-Icon', 'Bundle-License',
                      'Bundle-Localization', 'Bundle-ManifestVersion',
                      'Bundle-Name', 'Bundle-NativeCode',
                      'Bundle-RequiredExecutionEnvironment', 'Bundle-SCM',
                      'Bundle-SymbolicName', 'Bundle-UpdateLocation',
                      'Bundle-Vendor', 'Bundle-Version', 'DSTAMP',
                      'DynamicImport-Package', 'Export-Package',
                      'Export-Service', 'Fragment-Host', 'Extension-name',
                      'Import-Package', 'Import-Service', 'Provide-Capability',
                      'Require-Bundle', 'Require-Capability',
                      'Include-Resource', 'TODAY', 'Tool', 'TSTAMP']

    def parse(self):
        # open the file again, but then in text mode
        try:
            manifest_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            manifest_file.close()
            raise UnpackParserException(e.args)

        self.is_android = False

        data_unpacked = False
        len_unpacked = 0
        try:
            for manifest_line in manifest_file:
                line = manifest_line.rstrip()

                if line == '':
                    len_unpacked += len(manifest_line)
                    continue
                if line.startswith('#'):
                    len_unpacked += len(manifest_line)
                    continue

                # lines can be a continuation of a previous line
                if ':' not in line or line.startswith(' '):
                    try:
                        if re.match(r'\s+[\"; \-\.,\w\d/=:]+$', line) is not None:
                            len_unpacked += len(manifest_line)
                            continue
                        break
                    except:
                        break

                # then verify individual lines
                manifest_attribute = line.split(':')[0]
                if manifest_attribute in self.valid_attributes:
                    len_unpacked += len(manifest_line)
                    continue

                # check any digest values
                if manifest_attribute in ['SHA1-Digest', 'SHA-256-Digest']:
                    digest = line.split(':', 1)[1].strip()
                    try:
                        base64.b64decode(digest)
                        len_unpacked += len(manifest_line)
                        data_unpacked = True
                        continue
                    except Exception:
                        break

                # check a few exceptions
                valid_attribute = False

                for a in self.android_attributes:
                    if manifest_attribute.endswith(a):
                        valid_attribute = True
                        self.is_android = True
                        break
                if not valid_attribute:
                    for a in self.extension_attributes:
                        if manifest_attribute.endswith(a):
                            valid_attribute = True
                            break

                if not valid_attribute:
                    for a in self.custom_attributes:
                        if manifest_attribute.endswith(a):
                            valid_attribute = True
                            break
                if not valid_attribute:
                    for a in self.bnd_attributes:
                        if manifest_attribute.endswith(a):
                            valid_attribute = True
                            break
                if not valid_attribute:
                    # TODO: add more
                    break

                len_unpacked += len(manifest_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            manifest_file.close()

        check_condition(data_unpacked, "no manifest file data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['java_manifest']
    metadata = {}
