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

import rich
import rich.markdown
import rich.table

from bang.Reporter import Reporter


class ElfReporter(Reporter):
    tags = ['elf']
    pretty_name = 'elf'

    def create_report(self, md):
        title = rich.markdown.Markdown("## ELF")
        metadata = md.info.get('metadata')
        reports = []
        with md.open(open_file=False, info_write=False):
            meta_table = rich.table.Table('', '', title='ELF meta data', show_lines=True, show_header=False)
            elf_types = ", ".join(metadata['elf_type'])
            meta_table.add_row('ELF labels', f'{elf_types}')
            meta_table.add_row('Type', f'{metadata["type"]}')
            meta_table.add_row('Bits', f'{metadata["bits"]}')
            meta_table.add_row('Endianness', f'{metadata["endian"]}')
            meta_table.add_row('Machine name', f'{metadata["machine_name"]}')

            if 'telfhash' in metadata:
                meta_table.add_row('telfhash', f'{metadata["telfhash"]}')

            if 'security' in metadata:
                security_features = ", ".join(metadata['security'])
                meta_table.add_row('Security features', f'{security_features}')

            if 'needed' in metadata:
                needed = ", ".join(sorted(k['name'] for k in metadata['needed']))
                meta_table.add_row('Needed libraries', f'{needed}')

            # then lots of optional information
            if 'linker' in metadata:
                meta_table.add_row('Linker', f'{metadata["linker"]}')
            if 'rpath' in metadata:
                meta_table.add_row('RPATH', f'{metadata["rpath"]}')
            if 'runpath' in metadata:
                meta_table.add_row('RUNPATH', f'{metadata["runpath"]}')
            if 'soname' in metadata:
                meta_table.add_row('SONAME', f'{metadata["soname"]}')
            if 'build-id' in metadata:
                meta_table.add_row('Build id', f'{metadata["build-id"]}')
            if 'build-id hash' in metadata:
                meta_table.add_row('Build id hash', f'{metadata["build-id hash"]}')
            if 'gnu debuglink' in metadata:
                meta_table.add_row('GNU debug link', f'{metadata["gnu debuglink"]}')
            if 'gnu debuglink crc' in metadata:
                meta_table.add_row('GNU debug link CRC', f'{metadata["gnu debuglink crc"]}')
            if 'comment' in metadata:
                meta_table.add_row('Comment', "\n".join(metadata["comment"]))
            if 'package note' in metadata:
                if 'name' in metadata['package note']:
                    meta_table.add_row('Package name', f'{metadata["package note"]["name"]}')
                if 'version' in metadata['package note']:
                    meta_table.add_row('Package version', f'{metadata["package note"]["version"]}')
                if 'osCpe' in metadata['package note']:
                    meta_table.add_row('OS CPE', f'{metadata["package note"]["osCpe"]}')
            if 'strings' in metadata:
                if metadata['strings'] != []:
                    meta_table.add_row('Extracted strings', str(len(metadata['strings'])))
            if 'symbols' in metadata:
                if metadata['symbols'] != []:
                    meta_table.add_row('Extracted symbols', str(len(metadata['symbols'])))

            if 'Linux kernel module' in metadata['elf_type']:
                if 'Linux kernel module' in metadata:
                    if 'name' in metadata['Linux kernel module']:
                        meta_table.add_row('Module name', metadata['Linux kernel module']['name'])
                    if 'license' in metadata['Linux kernel module']:
                        meta_table.add_row('Module license', metadata['Linux kernel module']['license'])
                    if 'author' in metadata['Linux kernel module']:
                        meta_table.add_row('Module author', metadata['Linux kernel module']['author'])
                    if 'description' in metadata['Linux kernel module']:
                        meta_table.add_row('Module description', metadata['Linux kernel module']['description'])
                    if 'vermagic' in metadata['Linux kernel module']:
                        meta_table.add_row('Module version magic', metadata['Linux kernel module']['vermagic'])
                    if 'depends' in metadata['Linux kernel module']:
                        meta_table.add_row('Module depends on', ", ".join(metadata['Linux kernel module']['depends']))

            reports.append(meta_table)

            if 'sections' in metadata:
                meta_table = rich.table.Table('Number', 'Name', 'Type', 'Size', 'Offset', title='ELF section data', show_lines=True, show_header=True)
                for s in metadata['sections']:
                    if type(metadata['sections'][s]['type']) == int:
                        meta_table.add_row(str(metadata['sections'][s]['nr']), s, hex(metadata['sections'][s]['type']),
                                           str(metadata['sections'][s]['size']), str(metadata['sections'][s]['offset']))
                    else:
                        if metadata['sections'][s]['type'] == 'nobits':
                            meta_table.add_row(str(metadata['sections'][s]['nr']), s, metadata['sections'][s]['type'])
                        else:
                            meta_table.add_row(str(metadata['sections'][s]['nr']), s, metadata['sections'][s]['type'],
                                               str(metadata['sections'][s]['size']), str(metadata['sections'][s]['offset']))
                reports.append(meta_table)

        return title, reports
