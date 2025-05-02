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

import xml.dom
import defusedxml.minidom
from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


# There are a few variants of XML. The first one is the "regular"
# one, which is documented at:
# https://www.w3.org/TR/2008/REC-xml-20081126/
#
# Android has a "binary XML", where the XML data has been translated
# into a binary file. This is not supported by this parser.
class XmlUnpackParser(UnpackParser):
    extensions = ['.xml', '.xsd', '.ncx', '.opf', '.svg', '.rss']
    signatures = [
    ]
    pretty_name = 'xml'

    def parse(self):
        try:
            self.data = defusedxml.minidom.parse(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)

    labels = ['xml']
    metadata = {}
