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

from bang.Reporter import Reporter


class GifReporter(Reporter):
    tags = ['gif']
    pretty_name = 'gif'

    def create_report(self, md):
        '''Create markdown for GIF results'''
        new_markdown = '# GIF metadata\n'

        metadata = md.info.get('metadata')

        with md.open(open_file=False, info_write=False):
            new_markdown += "| | |\n|--|--|\n"
            new_markdown += f"**Width** | {metadata['width']}|\n"
            new_markdown += f"**Height** | {metadata['height']}|\n"

        return new_markdown
