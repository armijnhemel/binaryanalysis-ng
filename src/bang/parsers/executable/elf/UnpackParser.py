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

import binascii
import hashlib
import io
import json
import pathlib

import tlsh
import telfhash

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError, UndecidedEndiannessError
from . import elf
from . import zdebug

# a list of (partial) names of functions that have been
# compiled with FORTIFY_SOURCE. This list is not necessarily
# complete, but at least catches some verified functions.
FORTIFY_NAMES = ['cpy_chk', 'printf_chk', 'cat_chk', 'poll_chk',
                 'read_chk', '__memset_chk', '__memmove_chk',
                 'syslog_chk', '__longjmp_chk', '__fdelt_chk',
                 '__realpath_chk', '__explicit_bzero_chk', '__recv_chk',
                 '__getdomainname_chk', '__gethostname_chk']

# some names used in OCaml
OCAML_NAMES = ['caml_c_cal', 'caml_init_atom_table',
               'caml_init_backtrace', 'caml_init_custom_operations',
               'caml_init_domain', 'caml_init_frame_descriptors',
               'caml_init_gc', 'caml_init_ieee_floats',
               'caml_init_locale', 'caml_init_major_heap',
               'caml_init_signals', 'caml_sys_error',
               'caml_sys_executable_name', 'caml_sys_exit',
               'caml_sys_file_exists', 'caml_sys_get_argv',
               'caml_sys_get_config', 'caml_sys_getcwd',
               'caml_sys_getenv', 'caml_sys_init']

# road only data sections. This should be expanded.
RODATA_SECTIONS = ['.rodata', '.rodata.str1.1', '.rodata.str1.4',
                   '.rodata.str1.8', '.rodata.cst4', '.rodata.cst8',
                   '.rodata.cst16', 'rodata']

# sections with interesting data found in guile programs
GUILE_STRTAB_SECTIONS = ['.guile.arities.strtab', '.guile.docstrs.strtab']

# characters to be removed when extracting strings
REMOVE_CHARACTERS = ['\a', '\b', '\v', '\f', '\x01', '\x02', '\x03', '\x04',
                     '\x05', '\x06', '\x0e', '\x0f', '\x10', '\x11', '\x12',
                     '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19',
                     '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x7f']

REMOVE_CHARACTERS_TABLE = str.maketrans({'\a': '', '\b': '', '\v': '',
                                         '\f': '', '\x01': '', '\x02': '',
                                         '\x03': '', '\x04': '', '\x05': '',
                                         '\x06': '', '\x0e': '', '\x0f': '',
                                         '\x10': '', '\x11': '', '\x12': '',
                                         '\x13': '', '\x14': '', '\x15': '',
                                         '\x16': '', '\x17': '', '\x18': '',
                                         '\x19': '', '\x1a': '', '\x1b': '',
                                         '\x1c': '', '\x1d': '', '\x1e': '',
                                         '\x1f': '', '\x7f': ''
                                        })

# translation table for ASCII strings for the string
# to pass the isascii() test
STRING_TRANSLATION_TABLE = str.maketrans({'\t': ' '})

# hashes to compute for sections
HASH_ALGORITHMS = ['sha256', 'md5', 'sha1']


class ElfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x7f\x45\x4c\x46')
    ]
    pretty_name = 'elf'

    def parse(self):
        try:
            self.data = elf.Elf.from_io(self.infile)

            # calculate size, also read all the data to catch EOF
            # This isn't always accurate, for example when debugging
            # data is stored in ELF files as a compressed ELF file.
            phoff = self.data.header.program_header_offset
            self.unpacked_size = phoff
            for header in self.data.header.program_headers:
                # calculate the maximum offset
                self.unpacked_size = max(self.unpacked_size, header.offset + header.filesz)
                check_condition(self.unpacked_size <= self.infile.size,
                                "program header cannot be outside of file")

                # sanity check certain program headers,
                # specifically the dynamic section

            # TODO: Qualcomm DSP6 (Hexagon) files, as found on many
            # Android devices.

            # typically the section header is at the end of the ELF file
            shoff = self.data.header.section_header_offset
            self.unpacked_size = max(self.unpacked_size, shoff + self.data.header.qty_section_header
                                     * self.data.header.section_header_entry_size)
            check_condition(self.unpacked_size <= self.infile.size,
                            "section header cannot be outside of file")

            # first store the dynstr table as it is used for
            # symbol versioning
            self.dynstr = None
            num_dynsym = 0
            self.version_symbols = {}
            self.dependencies_to_versions = {}

            # store for each symbol which version is needed.
            # If there are no symbols, then this will stay empty
            self.symbol_to_version = {}
            self.version_to_name = {0: '', 1: ''}

            for header in self.data.header.section_headers:
                if header.type == elf.Elf.ShType.strtab:
                    if header.name == '.dynstr':
                        self.dynstr = io.BytesIO(header.raw_body)
                elif header.type == elf.Elf.ShType.dynsym:
                    if header.name == '.dynsym':
                        num_dynsym = len(header.body.entries)

            for header in self.data.header.section_headers:
                if header.type == elf.Elf.ShType.nobits:
                    continue
                self.unpacked_size = max(self.unpacked_size, header.ofs_body + header.len_body)

                # ugly ugly hack to work around situations on Android where
                # ELF files have been split into individual sections and all
                # offsets are wrong.
                if header.type == elf.Elf.ShType.note:
                    for entry in header.body.entries:
                        pass
                elif header.type == elf.Elf.ShType.strtab:
                    for entry in header.body.entries:
                        pass

                # force read the header name
                name = header.name
                if header.type == elf.Elf.ShType.symtab:
                    if header.name == '.symtab':
                        for entry in header.body.entries:
                            name = entry.name
                if header.type == elf.Elf.ShType.dynamic:
                    if header.name == '.dynamic':
                        for entry in header.body.entries:
                            if entry.tag_enum == elf.Elf.DynamicArrayTags.needed:
                                name = entry.value_str
                            elif entry.tag_enum == elf.Elf.DynamicArrayTags.rpath:
                                name = entry.value_str
                            elif entry.tag_enum == elf.Elf.DynamicArrayTags.runpath:
                                name = entry.value_str
                            elif entry.tag_enum == elf.Elf.DynamicArrayTags.soname:
                                name = entry.value_str

                # Symbols
                elif header.type == elf.Elf.ShType.symtab:
                    if header.name == '.symtab':
                        for entry in header.body.entries:
                            name = entry.name
                            name = entry.type.name
                            name = entry.bind.name
                            name = entry.visibility.name
                            name = entry.sh_idx
                            name = entry.size
                elif header.type == elf.Elf.ShType.dynsym:
                    if header.name == '.dynsym':
                        for entry in header.body.entries:
                            name = entry.name
                            name = entry.type.name
                            name = entry.bind.name
                            name = entry.visibility.name
                            name = entry.sh_idx
                            name = entry.size
                elif header.type == elf.Elf.ShType.progbits:
                    if header.name in RODATA_SECTIONS:
                        body = header.body

                # Symbol versioning
                # see https://johannst.github.io/notes/development/symbolver.html
                # for a good explanation of these symbols
                elif header.type == elf.Elf.ShType.gnu_versym:
                    if header.name == '.gnu.version':
                        check_condition(self.dynstr is not None, "no dynamic string section found")
                        check_condition(num_dynsym == len(header.body.symbol_versions),
                                        "mismatch between number of symbols and symbol versions")
                        self.symbol_to_version = {k: v.version for k, v in enumerate(header.body.symbol_versions)}
                elif header.type == elf.Elf.ShType.gnu_verneed:
                    if header.name == '.gnu.version_r':
                        check_condition(self.dynstr is not None, "no dynamic string section found")

                        cur_entry = header.body.entry
                        while True:
                            self.dynstr.seek(cur_entry.ofs_file_name_string)
                            try:
                                name = self.dynstr.read().split(b'\x00')[0].decode()
                                check_condition(name != '', "empty name")
                            except UnicodeDecodeError as e:
                                raise UnpackParserException(e.args)

                            self.dependencies_to_versions[name] = []

                            # verify the auxiliary entries
                            for a in cur_entry.auxiliary_entries:
                                self.dynstr.seek(a.ofs_name)
                                try:
                                    a_name = self.dynstr.read().split(b'\x00')[0].decode()
                                    check_condition(name != '', "empty name")
                                except UnicodeDecodeError as e:
                                    raise UnpackParserException(e.args)
                                self.version_to_name[a.object_file_version] = a_name
                                self.dependencies_to_versions[name].append(a_name)

                            # then jump to the next entry
                            if cur_entry.next is not None:
                                cur_entry = cur_entry.next
                            else:
                                break
                elif header.type == elf.Elf.ShType.gnu_verdef:
                    if header.name == '.gnu.version_d':
                        check_condition(self.dynstr is not None, "no dynamic string section found")
                        cur_entry = header.body.entry
                        self.version_to_name[0] = ''
                        ctr = 1
                        while True:
                            # verify the auxiliary entries. The only interesting one is
                            # actually the first name, the rest are "parents" (according
                            # to readelf)
                            aux_name = ''
                            for a in cur_entry.auxiliary_entries:
                                self.dynstr.seek(a.ofs_name)
                                try:
                                    a_name = self.dynstr.read().split(b'\x00')[0].decode()
                                    if aux_name == '':
                                        aux_name = a_name
                                    check_condition(name != '', "empty name")
                                except UnicodeDecodeError as e:
                                    raise UnpackParserException(e.args)

                            self.version_to_name[ctr] = aux_name
                            ctr += 1

                            # then jump to the next entry
                            if cur_entry.next is not None:
                                cur_entry = cur_entry.next
                            else:
                                break

            # read the names, but don't proces them. This is just to force
            # evaluation, which normally happens lazily for instances in
            # kaitai struct.
            names = self.data.header.section_names

            # TODO linux kernel module signatures
            # see scripts/sign-file.c in Linux kernel
        except (Exception, ValidationFailedError, UndecidedEndiannessError) as e:
            raise UnpackParserException(e.args)

        self.is_dynamic_elf = False
        if self.data.header.section_headers == []:
            self.has_section_headers = False
        else:
            self.has_section_headers = True


    def calculate_unpacked_size(self):
        pass

    def unpack(self, meta_directory):
        # there might be interesting data in some of the ELF sections
        # so write these to separate files to make available for
        # further analysis.
        #
        # TODO: write *all* ELF sections?
        #
        # There are some Android variants where the interesting data might
        # span multiple sections.
        for header in self.data.header.section_headers:
            if header.type == elf.Elf.ShType.progbits:
                interesting = False

                # * .gnu_debugdata: XZ compressed debugging information
                #
                # * .qtmimedatabase: compressed version of the freedesktop.org MIME database
                # * .BTF and .BTF.ext: eBPF related files
                # * .rom_info: Mediatek preloader(?)
                # * .init.data: Linux kernel init data, sometimes contains initial ramdisk
                if header.name in ['.gnu_debugdata', '.qtmimedatabase', '.BTF', '.BTF.ext', '.rom_info', '.init.data']:
                    interesting = True

                # GNOME/glib GVariant database
                if header.name.startswith('.gresource'):
                    interesting = True

                # GNU zdebug
                if header.name.startswith('.zdebug'):
                    interesting = True

                if not interesting:
                    continue

                file_path = pathlib.Path(header.name)
                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(header.body)

                    parent_name = pathlib.Path(self.infile.name)
                    # for some files some extra information should be
                    # passed to the downstream unpackers
                    if header.name == '.gnu_debugdata':
                        # MiniDebugInfo files:
                        # https://sourceware.org/gdb/onlinedocs/gdb/MiniDebugInfo.html
                        parent_name = pathlib.Path(self.infile.name)
                        with unpacked_md.open(open_file=False):
                            unpacked_md.info['propagated'] = {'parent': parent_name}
                            unpacked_md.info['propagated']['name'] = f'{parent_name.name}.debug'
                            unpacked_md.info['propagated']['type'] = 'MiniDebugInfo'
                    elif header.name == '.qtmimedatabase':
                        # Qt MIME database
                        with unpacked_md.open(open_file=False):
                            unpacked_md.info['propagated'] = {'parent': parent_name}
                            unpacked_md.info['propagated']['name'] = 'freedesktop.org.xml'
                            unpacked_md.info['propagated']['type'] = 'Qt MIME database'
                    elif header.name == '.BTF':
                        with unpacked_md.open(open_file=False):
                            unpacked_md.info['suggested_parsers'] = ['btf']
                    elif header.name == '.BTF.ext':
                        with unpacked_md.open(open_file=False):
                            unpacked_md.info['suggested_parsers'] = ['btf_ext']
                    elif header.name.startswith('.zdebug'):
                        with unpacked_md.open(open_file=False):
                            unpacked_md.info['suggested_parsers'] = ['zdebug']
                    yield unpacked_md

    def write_info(self, to_meta_directory):
        self.labels = ['elf']
        self.metadata = {}

        # generic bits first
        if self.data.bits == elf.Elf.Bits.b32:
            self.metadata['bits'] = 32
        elif self.data.bits == elf.Elf.Bits.b64:
            self.metadata['bits'] = 64

        # store the endianness
        if self.data.endian == elf.Elf.Endian.le:
            self.metadata['endian'] = 'little'
        elif self.data.endian == elf.Elf.Endian.be:
            self.metadata['endian'] = 'big'

        # store the ELF version
        self.metadata['version'] = self.data.ei_version

        # store the type of ELF file
        if self.data.header.e_type == elf.Elf.ObjType.no_file_type:
            self.metadata['type'] = None
        elif self.data.header.e_type == elf.Elf.ObjType.relocatable:
            self.metadata['type'] = 'relocatable'
        elif self.data.header.e_type == elf.Elf.ObjType.executable:
            self.metadata['type'] = 'executable'
        elif self.data.header.e_type == elf.Elf.ObjType.shared:
            self.metadata['type'] = 'shared'
        elif self.data.header.e_type == elf.Elf.ObjType.core:
            self.metadata['type'] = 'core'
        else:
            self.metadata['type'] = 'processor specific'

        # store the machine type, both numerical and pretty printed
        if type(self.data.header.machine) == int:
            self.metadata['machine_name'] = "unknown architecture"
            self.metadata['machine'] = self.data.header.machine
        else:
            self.metadata['machine_name'] = self.data.header.machine.name
            self.metadata['machine'] = self.data.header.machine.value

        # store the ABI, both numerical and pretty printed
        self.metadata['abi_name'] = self.data.abi.name
        self.metadata['abi'] = self.data.abi.value

        # then, depending on whether or not there are section headers
        # extract more data from the section headers or the program headers
        if self.has_section_headers:
            self.metadata = self.metadata | self.extract_metadata_and_labels_sections(to_meta_directory, self.metadata['endian'])
        else:
            pass

        elf_types = set(self.metadata.get('elf_type', []))
        if self.is_dynamic_elf:
            elf_types.add('dynamic')
        else:
            if self.metadata['type'] == 'core':
                elf_types.add('core')
            else:
                elf_types.add('static')

        self.metadata['elf_type'] = sorted(elf_types)

        if self.metadata['type'] in ['executable', 'shared']:
            try:
                telfhash_result = telfhash.telfhash(str(to_meta_directory.file_path))
                if telfhash_result != []:
                    telfhash_res = telfhash_result[0]['telfhash'].upper()
                    if telfhash_res != 'TNULL' and telfhash_res != '-':
                        self.metadata['telfhash'] = telfhash_res
            except UnicodeEncodeError:
                pass

        super().write_info(to_meta_directory)

    def extract_metadata_and_labels_sections(self, to_meta_directory, endian):
        '''Extract metadata from the ELF sections and set labels'''
        metadata = {}
        string_cutoff_length = 4

        security_metadata = set()

        # record the section names so they are easily accessible
        if self.data.header.section_names is not None:
            metadata['section_names'] = sorted(self.data.header.section_names.entries)

        # RELRO is a technique to mitigate some security vulnerabilities
        # http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/progheader.html
        seen_relro = False

        for header in self.data.header.program_headers:
            if header.type == elf.Elf.PhType.gnu_relro:
                security_metadata.add('relro')
                seen_relro = True
            elif header.type == elf.Elf.PhType.gnu_stack:
                # check to see if NX is set
                if not header.flags_obj.execute:
                    security_metadata.add('nx')
            elif header.type == elf.Elf.PhType.pax_flags:
                security_metadata.add('pax')

        # store the data normally extracted using for example 'strings'
        data_strings = []

        # store dependencies (empty for statically linked binaries)
        needed = []

        # store dynamic symbols (empty for statically linked binaries)
        dynamic_symbols = []

        # guile symbols (empty for non-Guile programs)
        guile_symbols = []

        # store information about notes
        notes = []

        # store symbols (empty for most binaries, except for
        # non-stripped binaries)
        symbols = []

        # module name (for Linux kernel modules)
        self.module_name = ''
        linux_kernel_module_info = {}

        # process the various section headers
        sections = {}
        section_ctr = 0
        elf_types = set()
        for header in self.data.header.section_headers:
            sections[header.name] = {}
            sections[header.name]['nr'] = section_ctr
            sections[header.name]['address'] = header.addr
            if type(header.type) == int:
                sections[header.name]['type'] = header.type
            else:
                sections[header.name]['type'] = header.type.name
            if header.type != elf.Elf.ShType.nobits:
                sections[header.name]['size'] = header.len_body
                sections[header.name]['offset'] = header.ofs_body
                if header.body != b'':
                    sections[header.name]['hashes'] = {}
                    for h in HASH_ALGORITHMS:
                        section_hash = hashlib.new(h)
                        section_hash.update(header.raw_body)
                        sections[header.name]['hashes'][h] = section_hash.hexdigest()

                    try:
                        tlsh_hash = tlsh.hash(header.raw_body)
                        if tlsh_hash != 'TNULL':
                            sections[header.name]['hashes']['tlsh'] = tlsh_hash
                    except:
                        pass

            section_ctr += 1

            if header.name in ['.modinfo', '__ksymtab_strings']:
                # TODO: find example where this data is only in __ksymtab_strings
                elf_types.add('Linux kernel module')
                try:
                    module_meta = header.body.split(b'\x00')
                    for m in module_meta:
                        meta = m.decode()
                        if meta == '':
                            continue
                        if meta.startswith('name='):
                            self.module_name = meta.split('=', maxsplit=1)[1]
                            linux_kernel_module_info['name'] = self.module_name
                        elif meta.startswith('license='):
                            self.module_name = meta.split('=', maxsplit=1)[1]
                            linux_kernel_module_info['license'] = self.module_name
                        elif meta.startswith('author='):
                            self.module_name = meta.split('=', maxsplit=1)[1]
                            linux_kernel_module_info['author'] = self.module_name
                        elif meta.startswith('description='):
                            self.module_name = meta.split('=', maxsplit=1)[1]
                            linux_kernel_module_info['description'] = self.module_name
                        elif meta.startswith('vermagic='):
                            self.module_name = meta.split('=', maxsplit=1)[1]
                            linux_kernel_module_info['vermagic'] = self.module_name
                        elif meta.startswith('depends='):
                            self.module_name = meta.split('=', maxsplit=1)[1]
                            if self.module_name != '':
                                if not 'depends' in linux_kernel_module_info:
                                    linux_kernel_module_info['depends'] = []
                                linux_kernel_module_info['depends'].append(self.module_name)
                except Exception as e:
                    pass
            elif header.name in ['.oat_patches', '.text.oat_patches', '.dex']:
                # OAT information has been stored in various sections
                # test files:
                # .oat_patches : fugu-lrx21m-factory-e012394c.zip
                elf_types.add('oat')
                elf_types.add('android')
            elif header.name in ['.guile.procprops', '.guile.frame-maps',
                                 '.guile.arities.strtab', '.guile.arities',
                                 '.guile.docstrs.strtab', '.guile.docstrs']:
                elf_types.add('guile')

            if header.type == elf.Elf.ShType.dynamic:
                if header.name == '.dynamic':
                    for entry in header.body.entries:
                        if entry.tag_enum == elf.Elf.DynamicArrayTags.needed:
                            needed.append({'name': entry.value_str, 'symbol_versions': self.dependencies_to_versions.get(entry.value_str, [])})
                        elif entry.tag_enum == elf.Elf.DynamicArrayTags.rpath:
                            metadata['rpath'] = entry.value_str
                        elif entry.tag_enum == elf.Elf.DynamicArrayTags.runpath:
                            metadata['runpath'] = entry.value_str
                        elif entry.tag_enum == elf.Elf.DynamicArrayTags.soname:
                            metadata['soname'] = entry.value_str
                        elif entry.tag_enum == elf.Elf.DynamicArrayTags.flags_1:
                            # check for position independent code
                            if entry.flag_1_values.pie:
                                security_metadata.add('pie')
                            # check for bind_now
                            if entry.flag_1_values.now:
                                if seen_relro:
                                    security_metadata.add('full relro')
                                else:
                                    security_metadata.add('partial relro')
                        elif entry.tag_enum == elf.Elf.DynamicArrayTags.flags:
                            # check for bind_now here as well
                            if entry.flag_values.bind_now:
                                if seen_relro:
                                    security_metadata.add('full relro')
                                else:
                                    security_metadata.add('partial relro')
            elif header.type == elf.Elf.ShType.symtab:
                if header.name == '.symtab':
                    for idx, entry in enumerate(header.body.entries):
                        symbol = {}
                        if entry.name is None:
                            symbol['name'] = ''
                        else:
                            symbol['name'] = entry.name
                        symbol['type'] = entry.type.name
                        symbol['binding'] = entry.bind.name
                        symbol['visibility'] = entry.visibility.name
                        symbol['section_index'] = entry.sh_idx
                        symbol['size'] = entry.size
                        symbols.append(symbol)
            elif header.type == elf.Elf.ShType.dynsym:
                if header.name == '.dynsym':
                    for idx, entry in enumerate(header.body.entries):
                        symbol = {}
                        if entry.name is None:
                            symbol['name'] = ''
                        else:
                            symbol['name'] = entry.name
                        symbol['binding'] = entry.bind.name
                        symbol['section_index'] = entry.sh_idx
                        symbol['size'] = entry.size
                        symbol['type'] = entry.type.name
                        symbol['value'] = entry.value
                        symbol['visibility'] = entry.visibility.name

                        # add versioning information, if any
                        if self.symbol_to_version != {}:
                            symbol['versioning'] = self.symbol_to_version[idx]
                            symbol['versioning_resolved_name'] = self.version_to_name[self.symbol_to_version[idx]]

                        # store dynamic symbols in *both* symbols and
                        # dynamic_symbols as they have a different scope.
                        symbols.append(symbol)
                        dynamic_symbols.append(symbol)

                        if symbol['name'] == 'oatdata':
                            elf_types.add('oat')
                            elf_types.add('android')

                        if symbol['name'] in OCAML_NAMES:
                            elf_types.add('ocaml')

                        # security related information
                        if symbol['name'] == '__stack_chk_fail':
                            security_metadata.add('stack smashing protector')
                        if '_chk' in symbol['name']:
                            if 'fortify' not in security_metadata:
                                for fortify_name in FORTIFY_NAMES:
                                    if symbol['name'].endswith(fortify_name):
                                        security_metadata.add('fortify')
                                        break

            elif header.type == elf.Elf.ShType.progbits:
                # process the various progbits sections here
                if header.name == '.comment':
                    # comment, typically in binaries that have
                    # not been stripped.
                    #
                    # The "strings" flag *should* be set for this section
                    # There could be multiple valid comments separated by \x00
                    # for example in some Android binaries
                    comment_components = list(filter(lambda x: x != b'', header.body.split(b'\x00')))
                    comments = []
                    for cc in comment_components:
                        try:
                            comment = cc.decode()
                            comments.append(comment)
                        except UnicodeDecodeError:
                            pass
                    if comments != []:
                        metadata['comment'] = comments
                elif header.name == '.gcc_except_table':
                    # debug information from GCC
                    pass
                elif header.name == '.gnu_debuglink':
                    # https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
                    try:
                        link_name = header.body.split(b'\x00', 1)[0].decode()
                        link_crc = int.from_bytes(header.body[-4:], byteorder=endian)
                        metadata['gnu debuglink'] = link_name
                        metadata['gnu debuglink crc'] = link_crc
                    except UnicodeDecodeError:
                        pass
                elif header.name == '.GCC.command.line':
                    # GCC -frecord-gcc-switches option
                    gcc_command_line_strings = []
                    for s in header.body.split(b'\x00'):
                        try:
                            gcc_command_line_strings.append(s.decode())
                        except UnicodeDecodeError:
                            pass
                    if gcc_command_line_strings != []:
                        metadata['.GCC.command.line'] = gcc_command_line_strings
                elif header.name in RODATA_SECTIONS:
                    for s in header.body.split(b'\x00'):
                        try:
                            decoded_strings = s.decode().splitlines()
                            for decoded_string in decoded_strings:
                                for rc in REMOVE_CHARACTERS:
                                    if rc in decoded_string:
                                        decoded_string = decoded_string.translate(REMOVE_CHARACTERS_TABLE)

                                if len(decoded_string) < string_cutoff_length:
                                    continue
                                if decoded_string.isspace():
                                    continue

                                translated_string = decoded_string.translate(STRING_TRANSLATION_TABLE)
                                if decoded_string.isascii():
                                    # test the translated string
                                    if translated_string.isprintable():
                                        data_strings.append(decoded_string)
                                else:
                                    data_strings.append(decoded_string)
                        except UnicodeDecodeError:
                            pass
                    # some Qt binaries use the Qt resource system,
                    # containing images, text, etc.
                    # Sometimes these end up in one of the .rodata ELF sections.
                    if b'qrc:/' in header.body:
                        pass
                elif header.name == '.interp':
                    # store the location of the dynamic linker
                    try:
                        metadata['linker'] = header.body.split(b'\x00', 1)[0].decode()
                    except UnicodeDecodeError:
                        pass

                # Some Go related things
                elif header.name == '.gopclntab':
                    # https://medium.com/walmartglobaltech/de-ofuscating-golang-functions-93f610f4fb76
                    pass
                elif header.name == '.gosymtab':
                    # Go symbol table
                    pass
                elif header.name == '.itablink':
                    # Go
                    pass
                elif header.name == '.noptrdata':
                    # Go pointer free data
                    pass
                elif header.name == '.typelink':
                    # Go
                    pass

                # QML and Qt
                elif header.name == '.qml_compile_hash':
                    pass
                elif header.name == '.qtmetadata':
                    pass
                elif header.name == '.qtversion':
                    pass

                elif header.name == '.tm_clone_table':
                    # something related to transactional memory
                    # http://gcc.gnu.org/wiki/TransactionalMemory
                    pass
                elif header.name == '.VTGData':
                    # VirtualBox tracepoint generated data
                    # https://www.virtualbox.org/browser/vbox/trunk/include/VBox/VBoxTpG.h
                    pass
                elif header.name == '.VTGPrLc':
                    pass
                elif header.name == '.rol4re_elf_aux':
                    # L4 specific
                    elf_types.add('l4')
                elif header.name == '.sbat':
                    # systemd, example linuxx64.elf.stub
                    # https://github.com/rhboot/shim/blob/main/SBAT.md
                    pass
                elif header.name == '.sdmagic':
                    # systemd, example linuxx64.elf.stub
                    try:
                        metadata['systemd loader'] = header.body.decode()
                    except UnicodeDecodeError:
                        pass
                elif header.name == 'sw_isr_table':
                    # Zephyr
                    elf_types.add('zephyr')
                elif header.name == 'protodesc_cold':
                    # Protobuf
                    elf_types.add('protobuf')

            if header.type == elf.Elf.ShType.dynamic:
                self.is_dynamic_elf = True
                for entry in header.body.entries:
                    pass
            elif header.type == elf.Elf.ShType.strtab:
                if header.name in GUILE_STRTAB_SECTIONS:
                    for entry in header.body.entries:
                        pass
                else:
                    for entry in header.body.entries:
                        pass
            elif header.type == elf.Elf.ShType.dynsym:
                for entry in header.body.entries:
                    pass
            elif header.type == elf.Elf.ShType.note:
                # Note sections can contain hints as to what is contained
                # in a binary or give information about the origin of the
                # binary, or the programming language.
                if header.name == '.note.go.buildid':
                    elf_types.add('go')

                # Although not common notes sections can be merged
                # with eachother. Example: .notes in Linux kernel images
                for entry in header.body.entries:
                    notes.append((entry.name.decode(), entry.type))
                    if entry.name == b'GNU' and entry.type == 1:
                        # https://raw.githubusercontent.com/wiki/hjl-tools/linux-abi/linux-abi-draft.pdf
                        # normally in .note.ABI.tag
                        major_version = int.from_bytes(entry.descriptor[4:8],
                                                       byteorder=endian)
                        patchlevel = int.from_bytes(entry.descriptor[8:12],
                                                    byteorder=endian)
                        sublevel = int.from_bytes(entry.descriptor[12:],
                                                  byteorder=endian)
                        metadata['linux_version'] = (major_version, patchlevel, sublevel)
                    elif entry.name == b'GNU' and entry.type == 3:
                        # normally in .note.gnu.build-id
                        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/developer_guide/compiling-build-id
                        buildid = binascii.hexlify(entry.descriptor).decode()
                        metadata['build-id'] = buildid
                        if len(buildid) == 40:
                            metadata['build-id hash'] = 'sha1'
                        elif len(buildid) == 32:
                            metadata['build-id hash'] = 'md5'
                    elif entry.name == b'GNU' and entry.type == 4:
                        # normally in .note.gnu.gold-version
                        try:
                            metadata['gold-version'] = entry.descriptor.split(b'\x00', 1)[0].decode()
                        except UnicodeDecodeError:
                            pass
                    elif entry.name == b'GNU' and entry.type == 5:
                        # normally in .note.gnu.property
                        pass
                    elif entry.name == b'Go' and entry.type == 4:
                        # normally in .note.go.buildid
                        # there are four hashes concatenated
                        # https://golang.org/pkg/cmd/internal/buildid/#FindAndHash
                        # http://web.archive.org/web/20210113145647/https://utcc.utoronto.ca/~cks/space/blog/programming/GoBinaryStructureNotes
                        pass
                    elif entry.name == b'Crashpad' and entry.type == 0x4f464e49:
                        # https://chromium.googlesource.com/crashpad/crashpad/+/refs/heads/master/util/misc/elf_note_types.h
                        pass
                    elif entry.name == b'stapsdt' and entry.type == 3:
                        # SystemTap probe descriptors
                        elf_types.add('SystemTap')
                    elif entry.name == b'Linux':
                        # .note.Linux as seen in some Linux kernel modules
                        elf_types.add('linux kernel')
                        if entry.type == 0x100:
                            # LINUX_ELFNOTE_BUILD_SALT
                            # see BUILD_SALT in init/Kconfig
                            try:
                                linux_kernel_module_info['kernel build id salt'] = entry.descriptor.decode()
                            except UnicodeDecodeError:
                                pass
                        elif entry.type == 0x101:
                            # LINUX_ELFNOTE_LTO_INFO
                            pass
                    elif entry.name == b'FDO' and entry.type == 0xcafe1a7e:
                        # https://fedoraproject.org/wiki/Changes/Package_information_on_ELF_objects
                        # https://systemd.io/COREDUMP_PACKAGE_METADATA/
                        # extract JSON and store it
                        try:
                            metadata['package note'] = json.loads(entry.descriptor.decode().split('\x00')[0].strip())
                        except:
                            pass
                    elif entry.name == b'FreeBSD':
                        elf_types.add('freebsd')
                    elif entry.name == b'OpenBSD':
                        elf_types.add('openbsd')
                    elif entry.name == b'NetBSD':
                        # https://www.netbsd.org/docs/kernel/elf-notes.html
                        elf_types.add('netbsd')
                    elif entry.name == b'Android' and entry.type == 1:
                        # https://android.googlesource.com/platform/ndk/+/master/parse_elfnote.py
                        elf_types.add('android')
                        metadata['android ndk'] = int.from_bytes(entry.descriptor, byteorder='little')
                    elif entry.name == b'Android' and entry.type == 4:
                        # .note.android.memtag
                        elf_types.add('android')
                    elif entry.name == b'Xen':
                        # http://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=xen/include/public/elfnote.h;h=181cbc4ec71c4af298e40c3604daff7d3b48d52f;hb=HEAD
                        # .note.Xen in FreeBSD kernel
                        # .notes in Linux kernel)
                        elf_types.add('xen')
                    elif entry.name == b'NaCl':
                        elf_types.add('Google Native Client')
                    elif entry.name == b'LLVM\x00\x00\x00\x00' and entry.type == 3:
                        # .notes.hwasan.globals
                        # https://source.android.com/docs/security/test/memory-safety/hwasan-reports
                        # https://reviews.llvm.org/D65770
                        pass

        if dynamic_symbols != []:
            metadata['dynamic_symbols'] = dynamic_symbols

        if guile_symbols != []:
            metadata['guile_symbols'] = guile_symbols

        if needed != []:
            metadata['needed'] = needed

        metadata['notes'] = notes
        metadata['security'] = sorted(security_metadata)

        if data_strings != []:
            metadata['strings'] = data_strings

        if symbols != []:
            metadata['symbols'] = symbols

        metadata['sections'] = sections

        if linux_kernel_module_info != {}:
            metadata['Linux kernel module'] = linux_kernel_module_info

        metadata['elf_type'] = sorted(elf_types)
        return metadata


class ZdebugUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ZLIB')
    ]
    pretty_name = 'zdebug'

    def parse(self):
        try:
            self.data = zdebug.Zdebug.from_io(self.infile)
            check_condition(self.data.len_data == len(self.data.data),
                            "declared length does not match length of uncompressed data")
        except (Exception, ValidationFailedError, UndecidedEndiannessError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        file_path = pathlib.Path(pathlib.Path(self.infile.name).name[2:])
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            outfile.write(self.data.data)
            yield unpacked_md

    labels = ['zdebug']
    metadata = {}
