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


class PngReporter(Reporter):
    tags = ['png']
    pretty_name = 'png'

    def create_report(self, md):
        '''Create markdown for PNG results'''
        new_markdown = '# PNG metadata\n'

        metadata = md.info.get('metadata')
        with md.open(open_file=False, info_write=False):
            new_markdown += "| | |\n|--|--|\n"
            new_markdown += f"**Width** | {metadata['width']}|\n"
            new_markdown += f"**Height** | {metadata['height']}|\n"
            new_markdown += f"**Depth** | {metadata['depth']}|\n"
            new_markdown += f"**Colour** | {metadata['color']}|\n"
            new_markdown += f"**Chunk names** | {', '.join(metadata['chunk_names'])}|\n"
            if metadata['png_type'] != []:
                new_markdown += f"**Type** | {', '.join(metadata['png_type'])}|\n"
            if metadata['unknownchunks'] != []:
                new_markdown += f"**Unknown chunks** | {', '.join(sorted(metadata['unknownchunks']))}|\n"

            # print any texts if available
            if 'text' in metadata:
                if metadata['text']:
                    new_markdown += '# PNG texts\n'
                    new_markdown += "|**Key**|**Value**|\n|--|--|\n"
                    for t in metadata['text']:
                        new_markdown += f"{t['key']} | {t['value']}|\n"

        return new_markdown
