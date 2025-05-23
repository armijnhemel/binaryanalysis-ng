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

import mutf8

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import java_class


class JavaClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xba\xbe')
    ]
    pretty_name = 'javaclass'

    def parse(self):
        try:
            self.data = java_class.JavaClass.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        # make sure that all the pointers
        # into the constant pool are actually valid
        constant_pool_index = 1
        for i in self.data.constant_pool:
            if i.is_prev_two_entries:
                constant_pool_index += 1
                continue
            if self.data.this_class == constant_pool_index:
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    pass

            try:
                if isinstance(i.cp_info, java_class.JavaClass.StringCpInfo):
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                pass
            except AttributeError as e:
                raise UnpackParserException(e.args) from e
            constant_pool_index += 1

    labels = ['java class']

    @property
    def metadata(self):
        # store the results for Java:
        # * methods
        # * interfaces (TODO)
        # * fields
        # * source file name
        # * class name
        # * strings
        metadata = {}
        metadata['flags'] = {}
        metadata['flags']['public'] = self.data.is_public
        metadata['flags']['final'] = self.data.is_final
        metadata['flags']['super'] = self.data.is_super
        metadata['flags']['interface'] = self.data.is_interface
        metadata['flags']['abstract'] = self.data.is_abstract
        metadata['flags']['synthetic'] = self.data.is_synthetic
        metadata['flags']['annotation'] = self.data.is_annotation
        metadata['flags']['enum'] = self.data.is_enum
        metadata['flags']['module'] = self.data.is_module

        # walk the constant pool for information that isn't
        # available some other way.
        metadata['strings'] = []
        constant_pool_index = 1
        for i in self.data.constant_pool:
            if i.is_prev_two_entries:
                constant_pool_index += 1
                continue
            if self.data.this_class == constant_pool_index:
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
                    metadata['classname'] = decoded_string
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    pass
            if isinstance(i.cp_info, java_class.JavaClass.StringCpInfo):
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
                    metadata['strings'].append(decoded_string)
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    pass
            constant_pool_index += 1

        #metadata['interfaces'] = []
        #for i in self.data.interfaces:
        #    try:
        #        decoded_string = mutf8.decode_modified_utf8(i.name_as_str)
        #        metadata['interfaces'].append(decoded_string)
        #    except (UnicodeDecodeError, AttributeError):
        #        pass

        metadata['fields'] = []
        for i in self.data.fields:
            try:
                decoded_string = mutf8.decode_modified_utf8(i.name_as_str)
                metadata['fields'].append(decoded_string)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                pass

        metadata['methods'] = []
        for i in self.data.methods:
            try:
                decoded_string = mutf8.decode_modified_utf8(i.name_as_str)
                metadata['methods'].append(decoded_string)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                pass

        for i in self.data.attributes:
            try:
                name = mutf8.decode_modified_utf8(i.name_as_str)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                continue

            if name == 'SourceFile':
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.info.sourcefile_as_str)
                    metadata['sourcefile'] = decoded_string
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    continue
        return metadata
