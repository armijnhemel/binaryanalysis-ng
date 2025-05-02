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

'''
QTI Chromatix is a proprietary format from Qualcomm. Its contents are used
to set parameters for various modules on a SoC, such as the camera module.
The format is not publicly known and also differs per version.

For example, in version 3.0.1 the data seems to be a list constructed
as follows:

* int32 (sequence number)
* name
* data

The exact list of names and structure of the data depends on the value of
the first name, which probably indicates the chip or the functionality. There
is no data in the file that allows to further parse the data, except by doing
a form of lookahead to see if there is another name.

Version 2.0.0 of the format seems to be completely different.
'''

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import qti_chromatix


class QtiChromatixUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QTI Chromatix Header'),
    ]
    pretty_name = 'qti_chromatix'

    def parse(self):
        try:
            self.data = qti_chromatix.QtiChromatix.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    labels = ['chromatix', 'resource']
    metadata = {}
