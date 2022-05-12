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

# Process ISO9660 file systems. It should be noted that this is not
# a complete implementation and there are quite a few different ways to
# confuse parsers, hide data and so on:
#
# https://www.sciencedirect.com/science/article/pii/S1742287610000435

import collections
import os
import pathlib
import zlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError, UndecidedEndiannessError
from . import iso9660
from . import zisofs

class Iso9660UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (32769, b'CD001')
    ]
    pretty_name = 'iso9660'

    def parse(self):
        self.zisofs = False
        self.apple_iso = False

        try:
            self.data = iso9660.Iso9660.from_io(self.infile)

            has_primary = False
            has_terminator = False

            # data structures for relocated directories
            self.relocated_to_parent_extent = {}
            self.extent_to_full_file = {}
            self.placeholders = set()

            # mapping between stored file names and alternate file names
            self.stored_filename_to_full_filename = {}

            # check the contents of the ISO image
            for descriptor in self.data.data_area:
                if descriptor.type == iso9660.Iso9660.VolumeType.primary:
                    # sanity checks: dates. This does not apply
                    # to all dates used in the specification.
                    check_condition(descriptor.volume.volume_creation_date_and_time.valid_date,
                                    "invalid creation date")

                    check_condition(descriptor.volume.volume_modification_date_and_time.valid_date,
                                    "invalid modification date")

                    self.block_size = descriptor.volume.logical_block_size.value

                    has_primary = True
                    iso_size = descriptor.volume.volume_space_size.value * self.block_size
                    check_condition(iso_size <= self.fileresult.filesize,
                                    "declared ISO9660 image bigger than file")

                    extent_size = descriptor.volume.root_directory.body.extent.value * self.block_size
                    check_condition(extent_size <= self.fileresult.filesize,
                                    "extent cannot be outside of file")

                    # process the root directory.

                    # ECMA 119, 7.6: file name for root directory is 0x00
                    # Some ISO file systems instead set it to 0x01, which
                    # according to 6.8.2.2 should not be for the first root
                    # entry.
                    # Seen in an ISO file included in an ASUS firmware file
                    # Modem_FW_4G_AC55U_30043808102_M14.zip

                    files = collections.deque()
                    if descriptor.volume.root_directory.body.directory_records is not None:
                        for record in descriptor.volume.root_directory.body.directory_records.records:
                            if record.len_dr == 0:
                                continue
                            if record.body.file_flags_directory:
                                if record.body.file_id not in ['\x00', '\x01']:
                                    files.append((record, pathlib.Path('')))
                            else:
                                files.append((record, pathlib.Path('')))

                    # process each file, perform various sanity checks
                    # and store useful metadata
                    while len(files) != 0:
                        record, cwd = files.popleft()
                        filename = record.body.file_id
                        full_filename = cwd / filename

                        extent_size = record.body.extent.value * descriptor.volume.logical_block_size.value
                        check_condition(extent_size <= self.fileresult.filesize,
                                        "extent cannot be outside of file")

                        # store if an entry is a zisofs file
                        is_zisofs_file = False

                        # store if an entry has been relocated
                        is_relocated = False
                        is_placeholder = False
                        is_symlink = False

                        try:
                            # process the various system use entries (mostly
                            # RockRidge), to extract interesting information

                            # SUSP entries can appear in different places.
                            # There can be "continuation area" entries with
                            # more entries, so first extract all the entries
                            # (including the ones in continuation areas) before
                            # processing.
                            su_entries = []

                            for entry in record.body.system_use.entries:
                                if entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.susp_continuation_area:
                                    old_offset = self.infile.tell()
                                    self.infile.seek(self.block_size * entry.susp_data.ca_location.value + entry.susp_data.ca_offset.value)
                                    susp_bytes = self.infile.read(entry.susp_data.ca_length.value)
                                    self.infile.seek(old_offset)

                                    # parse the continuation area
                                    continuation_area = iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.from_bytes(susp_bytes)

                                    # store all the entries
                                    for susp_entry in continuation_area.entries:
                                        su_entries.append(susp_entry)
                                else:
                                    su_entries.append(entry)

                            # store the alternate name, if any
                            alternate_name = ''

                            for entry in su_entries:
                                if entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.apple_attribute_list:
                                    self.apple_iso = True
                                elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_symbolic_link:
                                    is_symlink = True
                                elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_alternate_name:
                                    # TODO: extra sanity checks for the alternate
                                    # name and how to resolve if either 'parent'
                                    # or 'current' is set.
                                    if entry.susp_data.parent:
                                        alternate_name = '..'
                                    elif entry.susp_data.current:
                                        alternate_name = '.'
                                    else:
                                        alternate_name += entry.susp_data.name
                                elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_relocated_directory:
                                    is_relocated = True
                                elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_child_link:
                                    is_placeholder = True
                                elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrzf_zisofs:
                                    is_zisofs_file = True
                                    self.zisofs = True
                                    original_size = entry.susp_data.uncompressed_size.value
                                    zisofs_header_size_susp = entry.susp_data.header_size
                            if alternate_name != '':
                                if cwd in self.stored_filename_to_full_filename:
                                    cwd_name = self.stored_filename_to_full_filename[cwd]
                                else:
                                    cwd_name = cwd
                                self.stored_filename_to_full_filename[cwd / filename] = cwd_name / alternate_name
                                full_filename = cwd_name / alternate_name
                        except AttributeError:
                            pass

                        if is_placeholder:
                            self.placeholders.add(full_filename)
                        else:
                            if not is_symlink:
                                self.extent_to_full_file[record.body.extent.value] = full_filename

                        if is_relocated:
                            # sanity check the SUSP entries for the second
                            # directory item ('..'). According to the
                            # specifications:
                            #
                            # The "PL" System Use Entry shall be recorded in the
                            # System Use Area of the second Directory Record
                            # (".." entry) of each moved directory.
                            #
                            # TODO: the PL entry could be in a continuation area

                            # set parent to a dummy value. If there is a PL entry
                            # this will be overwritten with an actual value, so
                            # an easy sanity check would be to check if the
                            # dummy value has been changed.
                            parent = -1
                            for directory_record in record.body.directory_records.records:
                                if directory_record.len_dr == 0:
                                    continue
                                if directory_record.body.file_id == '\x01':
                                    for entry in directory_record.body.system_use.entries:
                                        if entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_parent_link:
                                            parent = entry.susp_data.lba_parent.value
                                            break
                                    break
                            check_condition(parent != -1, "invalid parent link")
                            self.relocated_to_parent_extent[full_filename] = parent

                        if not record.body.file_flags_directory:
                            if is_zisofs_file:
                                # sanity checks for zisofs files
                                try:
                                    zisofs_file = zisofs.Zisofs.from_bytes(record.body.file_content)
                                except ValidationFailedError:
                                    raise UnpackParserException(e.args)

                                # extra sanity checks
                                check_condition(original_size == zisofs_file.header.uncompressed_size,
                                                "zisofs uncompressed size mismatch")

                                zisofs_header_size = record.body.file_content[12]
                                check_condition(zisofs_header_size == zisofs_file.header.len_header,
                                                "zisofs header size mismatch")

                                check_condition(len(record.body.file_content) == zisofs_file.final_block_pointer,
                                                    "zisofs header size mismatch")

                                for block in zisofs_file.blocks:
                                    if block.len_block != 0:
                                        try:
                                            zlib.decompress(block.data)
                                        except zlib.error as e:
                                            raise UnpackParserException(e.args)

                        if record.body.directory_records is None:
                            continue
                        for dir_record in record.body.directory_records.records:
                            if dir_record.len_dr == 0:
                                continue
                            if dir_record.body.file_flags_directory:
                                if dir_record.body.file_id not in ['\x00', '\x01']:
                                    files.append((dir_record, cwd / filename))
                            else:
                                files.append((dir_record, cwd / filename))
                elif descriptor.type == iso9660.Iso9660.VolumeType.boot_record:
                    pass
                elif descriptor.type == iso9660.Iso9660.VolumeType.set_terminator:
                    # there should be at least one volume descriptor set terminator
                    has_terminator = True
        except (Exception, ValidationFailedError, UndecidedEndiannessError) as e:
            raise UnpackParserException(e.args)

        check_condition(has_primary, "no primary volume descriptor found")
        check_condition(has_terminator, "no volume descriptor set terminator found")

        # sanity checks for the relocated entries
        for f in self.relocated_to_parent_extent:
            extent = self.relocated_to_parent_extent[f]
            check_condition(extent in self.extent_to_full_file,
                            "invalid extent in relocated entries")

        # rewrite the names of entries in case there are relocated entries.
        # Do this in a loop as there might have been multiple levels of
        # relocation and those all need to be rewritten.
        rewritten_entries = set()
        while True:
            rewritten = False
            for f in self.relocated_to_parent_extent:
                extent = self.relocated_to_parent_extent[f]
                extent_name = self.extent_to_full_file[extent]
                new_entry_name = extent_name / f.name
                for name in self.stored_filename_to_full_filename:
                    if f == self.stored_filename_to_full_filename[name]:
                        self.stored_filename_to_full_filename[name] = new_entry_name
                        rewritten = True
                    elif self.stored_filename_to_full_filename[name].is_relative_to(f):
                        relative = self.stored_filename_to_full_filename[name].relative_to(f)
                        self.stored_filename_to_full_filename[name] = new_entry_name / relative
                        rewritten = True
            if not rewritten:
                break

        self.unpacked_size = iso_size

    def unpack(self):
        unpacked_files = []

        # check the contents of the ISO image
        for descriptor in self.data.data_area:
            if descriptor.type == iso9660.Iso9660.VolumeType.primary:

                # process the root directory.
                files = collections.deque()
                if descriptor.volume.root_directory.body.directory_records is not None:
                    for record in descriptor.volume.root_directory.body.directory_records.records:
                        if record.len_dr == 0:
                            continue
                        if record.body.file_flags_directory:
                            # add contentes, except for '.' and '..'
                            if record.body.file_id not in ['\x00', '\x01']:
                                files.append((record, pathlib.Path('')))
                        else:
                            files.append((record, pathlib.Path('')))

                while len(files) != 0:
                    record, cwd = files.popleft()
                    filename = record.body.file_id
                    if cwd / filename in self.stored_filename_to_full_filename:
                        full_filename = self.stored_filename_to_full_filename[cwd / filename]
                    else:
                        full_filename = cwd / filename
                    is_symlink = False

                    # store if an entry is a zisofs file
                    is_zisofs_file = False

                    # store if an entry has been relocated
                    is_relocated = False
                    is_placeholder = False

                    # process the various system use entries, mostly from RockRidge
                    try:
                        # process symbolic links. There can be multiple SL fields
                        # and together these make up the symbolic link target.
                        # To make things even more interesting each individual
                        # component can be continued as well.
                        symbolic_link_components = []
                        symbolic_current_component = ''
                        symbolic_current_component_continue = False

                        # store the interesting entries first before processing
                        su_entries = []

                        for entry in record.body.system_use.entries:
                            if entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.susp_continuation_area:
                                # store all the continuation area entries to
                                # the list of entries that need to be processed
                                # as well.
                                old_offset = self.infile.tell()
                                self.infile.seek(self.block_size * entry.susp_data.ca_location.value + entry.susp_data.ca_offset.value)
                                susp_bytes = self.infile.read(entry.susp_data.ca_length.value)
                                self.infile.seek(old_offset)

                                continuation_area = iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.from_bytes(susp_bytes)

                                # store all the continuation area entries to
                                # the list of entries that need to be processed
                                # as well.
                                for susp_entry in continuation_area.entries:
                                    su_entries.append(susp_entry)
                            else:
                                su_entries.append(entry)

                        for entry in su_entries:
                            if entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_symbolic_link:
                                is_symlink = True
                                for component in entry.susp_data.component_records:
                                    # first determine the component
                                    if component.current:
                                        component_name = '.'
                                    elif component.parent:
                                        component_name = '..'
                                    elif component.root:
                                        component_name = '/'
                                    else:
                                        component_name = component.content

                                    if symbolic_current_component_continue:
                                        symbolic_current_component += component_name
                                        if not component.continued:
                                            symbolic_link_components.append(symbolic_current_component)
                                            symbolic_current_component = ''
                                            continue
                                    else:
                                        if component.continued:
                                            symbolic_current_component = component_name
                                        else:
                                            symbolic_link_components.append(component_name)
                                            symbolic_current_component = ''
                                    symbolic_current_component_continue = component.continued
                            elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_child_link:
                                is_placeholder = True
                            elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrip_relocated_directory:
                                is_relocated = True
                            elif entry.signature == iso9660.Iso9660.VolumeDescriptor.DirectoryRecord.Body.Susp.Header.Signature.rrzf_zisofs:
                                is_zisofs_file = True
                                original_size = entry.susp_data.uncompressed_size.value
                                zisofs_header_size_susp = entry.susp_data.header_size

                        if symbolic_link_components != []:
                            symbolic_target_name = pathlib.Path(*symbolic_link_components)
                    except AttributeError:
                        # there are no entries in the system use
                        # field or there is no system use field.
                        pass

                    if not record.body.file_flags_directory:
                        # regular files, symlinks, etc.
                        outfile_rel = self.rel_unpack_dir / full_filename
                        outfile_full = self.scan_environment.unpack_path(outfile_rel)
                        os.makedirs(outfile_full.parent, exist_ok=True)

                        # create files/links but only if they are not
                        # placeholder files (for relocated directories)
                        if not is_placeholder:
                            if is_symlink:
                                outfile_full.symlink_to(symbolic_target_name)
                                fr = FileResult(self.fileresult, outfile_rel, set(['symbolic link']))
                            else:
                                outfile = open(outfile_full, 'wb')
                                if is_zisofs_file:
                                    zisofs_file = zisofs.Zisofs.from_bytes(record.body.file_content)

                                    for block in zisofs_file.blocks:
                                        if block.len_block == 0:
                                            outfile.seek( zisofs_file.header.block_size)
                                        else:
                                            outfile.write(zlib.decompress(block.data))

                                    # in case more bytes were written because the last
                                    # block with NUL bytes actually should not have been
                                    # a full block.
                                    outfile.truncate(original_size)
                                else:
                                    outfile.write(record.body.file_content)

                                outfile.close()
                                fr = FileResult(self.fileresult, outfile_rel, set())
                            unpacked_files.append(fr)
                    else:
                        outfile_rel = self.rel_unpack_dir / full_filename
                        outfile_full = self.scan_environment.unpack_path(outfile_rel)
                        os.makedirs(outfile_full, exist_ok=True)

                        # add the contents of a directory to the queue
                        for dir_record in record.body.directory_records.records:
                            # skip empty directory records
                            if dir_record.len_dr == 0:
                                continue

                            if dir_record.body.file_flags_directory:
                                # add contentes, except for '.' and '..'
                                if dir_record.body.file_id not in ['\x00', '\x01']:
                                    files.append((dir_record, cwd / filename))
                            else:
                                files.append((dir_record, cwd / filename))
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    # no need to carve from the file
    def carve(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['iso9660', 'filesystem']
        metadata = {}

        for volume_descriptor in self.data.data_area:
            if volume_descriptor.type == iso9660.Iso9660.VolumeType.primary:
                pass
            elif volume_descriptor.type == iso9660.Iso9660.VolumeType.boot_record:
                metadata['bootable'] = True

        if self.apple_iso:
            metadata['apple extensions'] = True
        if self.zisofs:
            metadata['zisofs'] = True

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
