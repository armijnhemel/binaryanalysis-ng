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

# Python PKG-INFO file parsing
# Described in PEP-566:
# https://www.python.org/dev/peps/pep-0566/
# https://packaging.python.org/en/latest/specifications/core-metadata/

import email.parser

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class PythonPkginfoUnpackParser(UnpackParser):
    extensions = ['pkg-info']
    signatures = [
    ]
    pretty_name = 'python_pkginfo'

    valid_versions = ['1.0', '1.1', '1.2', '2.1', '2.2', '2.3']
    strict_check = False

    # the various PEP specifications define mandatory items but in
    # practice these are not followed: many mandatory items are
    # simply not present and items defined in later versions are.
    # This could be because the PEPs are a bit ambigious and/or
    # tools/packagers are sloppy.

    # https://www.python.org/dev/peps/pep-0241/
    mandatory_10 = set(['Metadata-Version', 'Name', 'Version', 'Platform',
                        'Summary', 'Author-email', 'License',
                        'Supported-Platform'])

    optional_10 = optional_11 = set(['Description', 'Keywords',
                                     'Home-page', 'Author'])

    # https://www.python.org/dev/peps/pep-0314/
    mandatory_11_new = set(['Download-URL', 'Classifier', 'Requires',
                            'Provides', 'Obsoletes'])
    mandatory_11 = mandatory_10 | mandatory_11_new

    # version 1.2 and 2.1 have the same mandatory fields
    # https://www.python.org/dev/peps/pep-0345/
    # https://www.python.org/dev/peps/pep-0566/
    mandatory_12_new = set(['Download-URL', 'Classifier'
                            'Requires-Dist', 'Provides-Dist',
                            'Obsoletes-Dist', 'Requires-Python',
                            'Requires-External', 'Project-URL'])
    mandatory_12 = mandatory_11 | mandatory_12_new

    optional_12_new = set(['Author-email', 'Maintainer',
                           'Maintainer-email', 'License'])
    optional_12 = optional_11 | optional_12_new

    optional_21_new = set(['Description-Content-Type',
                           'Provides-Extra'])
    optional_21 = optional_12 | optional_21_new

    # https://peps.python.org/pep-0639/
    non_standard = set(['License-File'])

    metadata_to_mandatory = {'1.0': mandatory_10,
                             '1.1': mandatory_11,
                             '1.2': mandatory_12,
                             '2.1': mandatory_12,
                             '2.2': mandatory_12,
                             '2.3': mandatory_12}
    metadata_to_optional = {'1.0': optional_10,
                            '1.1': optional_11,
                            '1.2': optional_12,
			    '2.1': optional_21,
                            '2.2': optional_21,
                            '2.3': optional_21}

    # TODO: probably this can just be rewritten to optional_21
    all_optional = optional_11 | optional_12 | optional_21 | non_standard

    def parse(self):
        # open the file again, but then in text mode
        try:
            pkg_info_file = open(self.infile.name, 'r', newline='')
            header_parser = email.parser.HeaderParser()
            headers = header_parser.parse(pkg_info_file)

        except Exception as e:
            pkg_info_file.close()
            raise UnpackParserException(e.args) from e

        # then some sanity checks
        check_condition('Metadata-Version' in headers, 'Metadata-Version missing')

        metadata_version = headers['Metadata-Version']
        check_condition(metadata_version in self.valid_versions, 'Metadata-Version invalid')

        # keep track which mandatory items are missing
        missing = set()

        unknown = set()

        # keep track of which items are in the wrong version
        wrong_version = set()

        for i in self.metadata_to_mandatory[metadata_version]:
            if self.strict_check:
                check_condition(i in headers, f'{i} missing')
            for i in headers:
                if not (i in self.metadata_to_mandatory[metadata_version] or i in self.metadata_to_optional[metadata_version]):
                    if i in self.all_optional:
                        wrong_version.add(i)
                    else:
                        unknown.add(i)

        self.unpacked_size = self.infile.size

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['python pkg-info']
    metadata = {}
