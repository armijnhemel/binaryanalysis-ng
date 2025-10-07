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


class ElfReporter(Reporter):
    tags = ['elf']
    pretty_name = 'elf'

    def create_report(self, md):
        '''Create markdown for ELF results'''
        new_markdown = '# ELF metadata\n'
        metadata = md.info.get('metadata')
        with md.open(open_file=False, info_write=False):
            elf_types = ", ".join(metadata['elf_type'])

            new_markdown += "| | |\n|--|--|\n"
            new_markdown += f"**ELF labels** | {elf_types}|\n"
            new_markdown += f"**Type** | {metadata['type']}|\n"
            new_markdown += f"**Bits** | {metadata['bits']}|\n"
            new_markdown += f"**Endianness** | {metadata['endian']}|\n"
            new_markdown += f"**Machine name** | {metadata['machine_name']}|\n"

            if 'telfhash' in metadata:
                new_markdown += f"**telfhash** | {metadata['telfhash']}|\n"

            if 'security' in metadata:
                security_features = ", ".join(metadata['security'])
                new_markdown += f"**Security features** | {security_features}|\n"

            # then lots of optional information
            if 'linker' in metadata:
                new_markdown += f"**Linker** | {metadata['linker']}|\n"
            if 'rpath' in metadata:
                new_markdown += f"**RPATH** | {metadata['rpath']}|\n"
            if 'runpath' in metadata:
                new_markdown += f"**RUNPATH** | {metadata['runpath']}|\n"
            if 'soname' in metadata:
                new_markdown += f"**SONAME** | {metadata['soname']}|\n"
            if 'build-id' in metadata:
                new_markdown += f"**Build id** | {metadata['build-id']}|\n"
            if 'build-id hash' in metadata:
                new_markdown += f"**Build id hash** | {metadata['build-id hash']}|\n"
            if 'gnu debuglink' in metadata:
                new_markdown += f"**GNU debug link** | {metadata['gnu debuglink']}|\n"
            if 'gnu debuglink crc' in metadata:
                new_markdown += f"**GNU debug link CRC** | {metadata['gnu debuglink crc']}|\n"
            if 'comment' in metadata:
                comm = "\n".join(sorted(set(metadata['comment'])))
                new_markdown += f"**Comment** | {comm}|\n"
            if 'strings' in metadata:
                if metadata['strings'] != []:
                    new_markdown += f"**Extracted strings** | {len(metadata['strings'])}|\n"
            if 'symbols' in metadata:
                if metadata['symbols'] != []:
                    new_markdown += f"**Extracted symbols** | {len(metadata['symbols'])}|\n"

            if 'Linux kernel module' in metadata['elf_type']:
                if 'Linux kernel module' in metadata:
                    field_to_label = {'name': 'Module name',
                                      'license': 'Module license',
                                      'author': 'Module author',
                                      'description': 'Module description',
                                      'vermagic': 'Module version magic',
                                      'depends': 'Module depends on',
                                     }
                    for field in field_to_label:
                        if field in metadata['Linux kernel module']:
                            new_markdown += f"**{field_to_label[field]}** | {metadata['Linux kernel module'][field]}|\n"

            if 'needed' in metadata:
                new_markdown += "# Needed libraries\n"
                new_markdown += "|Name|Symbol versions|\n|--|--|\n"

                for n in sorted(metadata['needed'], key=lambda x: x['name']):
                    symbol_versions = sorted(n['symbol_versions'])
                    new_markdown += f"{n['name']}|{", ".join(symbol_versions)}|\n"

            if 'package note' in metadata:
                new_markdown += "# Package note\n"
                new_markdown += "| | |\n|--|--|\n"
                if 'name' in metadata['package note']:
                    new_markdown += f"**Package name** | {metadata['package note']['name']}|\n"
                if 'version' in metadata['package note']:
                    new_markdown += f"**Package version** | {metadata['package note']['version']}|\n"
                if 'osCpe' in metadata['package note']:
                    new_markdown += f"**OS CPE** | {metadata['package note']['osCpe']}|\n"


            if 'sections' in metadata:
                new_markdown += "# ELF sections\n"
                new_markdown += "|Number|Name|Type|Size|Offset|\n|--|--|--|--|--|\n"
                for s in metadata['sections']:
                    section_nr = metadata['sections'][s]['nr']
                    section_type = metadata['sections'][s]['type']

                    if metadata['sections'][s]['defined_type']:
                        if metadata['sections'][s]['type'] == 'nobits':
                            new_markdown += f"{section_nr}|{s}|{section_type}| | |\n"
                            continue

                    section_size = metadata['sections'][s]['size']
                    section_offset = metadata['sections'][s]['offset']

                    if not metadata['sections'][s]['defined_type']:
                        new_markdown += f"{section_nr}|{s}|{hex(section_type)}|{section_size}|{section_offset}|\n"
                    else:
                        new_markdown += f"{section_nr}|{s}|{section_type}|{section_size}|{section_offset}|\n"

        return new_markdown
