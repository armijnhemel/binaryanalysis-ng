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

# verify pkg-config files
# man 5 pc

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class PkgConfigUnpackParser(UnpackParser):
    extensions = ['.pc']
    signatures = [
    ]
    pretty_name = 'pkg-config'

    # lists of known property keywords from # the pkg-config specification
    # split into mandatory keywords and optional keywords.
    #
    # The specification actually says 'URL' is mandatory,
    # but many files leave it out so here it is labeled as optional
    mandatory_keywords = set(['Name', 'Version', 'Description'])
    optional_keywords = set(['Cflags', 'Cflags.private', 'Libs', 'Libs.private',
                             'Requires', 'Requires.private', 'Conflicts',
                             'Provides', 'URL'])

    def parse(self):
        # open the file again, but then in text mode
        try:
            pkg_config_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            pkg_config_file.close()
            raise UnpackParserException(e.args) from e

        self.keywords_found = set()

        data_unpacked = False
        len_unpacked = 0
        continued = False
        try:
            for pkg_config_line in pkg_config_file:
                line = pkg_config_line.rstrip()

                if line == '':
                    len_unpacked += len(pkg_config_line)
                    continued = False
                    continue
                if line.startswith('#'):
                    len_unpacked += len(pkg_config_line)
                    continued = False
                    continue

                if continued:
                    len_unpacked += len(pkg_config_line)
                    if not line.endswith('\\'):
                        continued = False
                    continue

                # key/value are separated by :
                fields = line.split(':', 1)
                keyword_found = False

                for k in self.mandatory_keywords | self.optional_keywords:
                    if k == fields[0]:
                        self.keywords_found.add(k)
                        keyword_found = True
                        continued = False
                        if line.endswith('\\'):
                            continued = True
                        break
                if keyword_found:
                    len_unpacked += len(pkg_config_line)
                    continue

                # then process variable definitions
                if '=' not in line:
                    break

                #fields = line.split('=', 1)
                # TODO: process further

                if line.endswith('\\'):
                    continued = True

                len_unpacked += len(pkg_config_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            pkg_config_file.close()

        check_condition(data_unpacked, "no pkg-config data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['pkg-config']
    metadata = {}
