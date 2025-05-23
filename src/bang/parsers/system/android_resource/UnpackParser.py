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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_resource


class AndroidResourceUnpackParser(UnpackParser):
    # extensions are mostly for resources.arsc,
    # signatures are for Android binary XML
    extensions = ['resources.arsc']
    signatures = [
        (0, b'\x03\x00\x08\x00')
    ]
    pretty_name = 'android_resource'

    def parse(self):
        try:
            self.data = android_resource.AndroidResource.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e
        if self.data.resource.header.type == android_resource.AndroidResource.ResourceTypes.xml:
            # walk to see if the XML is actually correct
            elem_count = 0
            namespace_count = 0
            check_condition(self.data.resource.body.body.nodes != [],
                            "no elements found")
            for node in self.data.resource.body.body.nodes:
                if node.header.type == android_resource.AndroidResource.ResourceTypes.xml_start_element:
                    elem_count += 1
                elif node.header.type == android_resource.AndroidResource.ResourceTypes.xml_end_element:
                    elem_count -= 1
                elif node.header.type == android_resource.AndroidResource.ResourceTypes.xml_start_namespace:
                    namespace_count += 1
                elif node.header.type == android_resource.AndroidResource.ResourceTypes.xml_end_namespace:
                    namespace_count -= 1
                check_condition(elem_count >= 0, "unbalanced XML elements")
                check_condition(namespace_count >= 0, "unbalanced XML namespace")

    @property
    def labels(self):
        labels = ['resource', 'android resource', 'android']
        metadata = {}

        if self.data.resource.header.type == android_resource.AndroidResource.ResourceTypes.xml:
            labels.append('binary xml')

        return labels

    metadata = {}
