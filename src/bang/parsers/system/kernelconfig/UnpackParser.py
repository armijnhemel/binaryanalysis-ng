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

# Kernel configuration files are frequently embedded in Linux kernel images

import re

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class LinuxKernelConfigUnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    pretty_name = 'kernelconfig'
    scan_if_featureless = True

    # The header line was changed in Linux kernel commit
    # e54e692ba613c2170c66ce36a3791c009680af08
    header_re = re.compile(r'# Automatically generated make config: don\'t edit$')
    header_re_alt = re.compile(r'# Automatically generated file; DO NOT EDIT.$')

    # some regex for grabbing additional information from the data
    header_version_re = re.compile(r'# Linux kernel version: ([\d\.]+)$')
    header_version_re_alt = re.compile(r'# Linux/[\w\d\-_]+ ([\d\w\.\-_]+) Kernel Configuration$')
    header_date_re = re.compile(r'# (\w{3} \w{3} [\d ]+ \d{2}:\d{2}:\d{2} \d{4})$')
    header_compiler_re = re.compile(r'# Compiler: ([\w\d\.\-() ]+)$')

    # regular expression for the configuration header lines
    config_header_re = re.compile(r'# [\w\d/\-;:\. ,()&+\'>]+$')

    # regular expressions for the lines with configuration
    commented_config_re = re.compile(r'# CONFIG_[\w\d_]+ is not set$')
    config_re = re.compile(r'(CONFIG_[\w\d_]+)=([ynm])$')
    config_re2 = re.compile(r'(CONFIG_[\w\d_]+)=([\w\d"\-/\.$()+ =,]+$)')

    def parse(self):
        # open the file again, but then in text mode
        try:
            kernel_config_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            kernel_config_file.close()
            raise UnpackParserException(e.args) from e

        self.header = {}
        self.configurations = {}

        data_unpacked = False
        len_unpacked = 0

        header_found = False
        kernel_config_found = False

        # A valid kernel configuration typicaly consists of
        # main header followed by sections.
        # 
        # Sections typically have a header, followed by
        # configuration statements, which could be commented,
        # and there can be empty lines too.
        #
        # Anything that is commented (main header, section headers,
        # commented configurations, other comments) are optional.
        #
        # For fingerprinting purposes it actually is good to at least
        # try to match the main header.
        try:
            for kernel_config_line in kernel_config_file:
                line_matched = False
                line = kernel_config_line.rstrip()

                # skip empty lines
                if line == '':
                    len_unpacked += len(kernel_config_line)
                    continue

                # skip empty comment lines
                if line == '#':
                    len_unpacked += len(kernel_config_line)
                    continue

                # comments could either be:
                # * main header
                # * configuration headers
                # * commented configuration options
                if line.startswith('#'):
                    if self.commented_config_re.match(line) is not None:
                        # require a header
                        if not header_found:
                            break
                        kernel_config_found = True
                        line_matched = True
                    else:
                        if self.header_re.match(line) is not None:
                            line_matched = True
                            header_found = True
                        elif self.header_re_alt.match(line) is not None:
                            line_matched = True
                            header_found = True
                        elif self.header_version_re.match(line) is not None:
                            kernel_version = self.header_version_re.match(line).groups()[0]
                            self.header['version'] = kernel_version
                            line_matched = True
                            header_found = True
                        elif self.header_version_re_alt.match(line) is not None:
                            kernel_version = self.header_version_re_alt.match(line).groups()[0]
                            self.header['version'] = kernel_version
                            line_matched = True
                            header_found = True
                        elif self.header_date_re.match(line) is not None:
                            kernel_date = self.header_date_re.match(line).groups()[0]
                            self.header['date'] = kernel_date
                            line_matched = True
                            header_found = True
                        elif self.header_compiler_re.match(line) is not None:
                            compiler = self.header_compiler_re.match(line).groups()[0]
                            self.header['compiler'] = compiler
                            line_matched = True
                            header_found = True
                        else:
                            if self.config_header_re.match(line) is not None:
                                line_matched = True
                else:
                    if self.config_re.match(line) is None:
                        if self.config_re2.match(line) is not None:
                            (conf, val) = self.config_re2.match(line).groups()
                            self.configurations[conf] = val
                            line_matched = True
                            kernel_config_found = True
                    else:
                        (conf, val) = self.config_re.match(line).groups()
                        self.configurations[conf] = val
                        line_matched = True
                        kernel_config_found = True
                if not line_matched:
                    break

                len_unpacked += len(kernel_config_line)
                if header_found:
                    data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args) from e
        finally:
            kernel_config_file.close()

        check_condition(data_unpacked, "no Linux kernel configuration data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['linux kernel configuration']

    @property
    def metadata(self):
        metadata = {'header': self.header, 'configurations': self.configurations}
        return metadata
