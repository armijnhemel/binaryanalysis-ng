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
# SPDX-License-Identifier: GPL-3.0-only

import os
import queue
import sys
import threading
import traceback
import time
from dataclasses import dataclass
from .meta_directory import *
from .UnpackParser import SynthesizingParser, ExtractedParser, ExtractingParser, PaddingParser, StringExtractingParser, TlshParser, compute_hashes
from .UnpackParserException import UnpackParserException
from .log import log


class ScanJob:
    def __init__(self, path):
        self._path = path
        self._meta_directory = None
        self.scan_environment = None

    @property
    def meta_directory(self):
        if self._meta_directory is None:
            self._meta_directory = MetaDirectory.from_md_path(self.scan_environment.unpack_directory, self._path)
        return self._meta_directory

#####
#
# Returns if a path is a scannable file, i.e. a regular file and not empty.
#
def is_scannable(path):
    return path.is_file() and path.stat().st_size != 0

#####
#
# Returns if a path is an empty file, i.e. a regular file and empty.
#
def is_empty(path):
    return path.is_file() and path.stat().st_size == 0

#####
#
# Extracts in_file[offset:offset+file_size] in checking_meta_directory.
#
def extract_file(checking_meta_directory, in_file, offset, file_size):
    # TODO: check if offset and file_size parameters are still needed in next line
    with checking_meta_directory.extract_file(offset, file_size) as (extracted_md, extracted_file):
        if file_size > 2147479552:
            bytes_left = file_size
            bytes_to_write = min(bytes_left, 2147479552)
            read_offset = offset
            while bytes_left > 0:
                os.sendfile(extracted_file.fileno(), in_file.fileno(), read_offset, bytes_to_write)
                bytes_left -= bytes_to_write
                read_offset += bytes_to_write
                bytes_to_write = min(bytes_left, 2147479552)
        else:
            os.sendfile(extracted_file.fileno(), in_file.fileno(), offset, file_size)
    return extracted_md

#####
#
# Iterator that checks if the file for checking_meta_directory is a padding file.
# Yields checking_meta_directory if this is the case.
#
def check_for_padding(scan_environment, checking_meta_directory):
    try:
        unpack_parser = PaddingParser(checking_meta_directory, 0, scan_environment.configuration)
        log.debug(f'check_for_padding[{checking_meta_directory.md_path}]: trying parse for {checking_meta_directory.file_path} with {unpack_parser.__class__} [{time.time_ns()}]')
        unpack_parser.parse_from_offset()
        log.debug(f'check_for_padding[{checking_meta_directory.md_path}]: successful parse for {checking_meta_directory.file_path} with {unpack_parser.__class__} [{time.time_ns()}]')
        log.debug(f'check_for_padding[{checking_meta_directory.md_path}]: parsed_size = {unpack_parser.parsed_size}/{checking_meta_directory.size}')
        if unpack_parser.parsed_size == checking_meta_directory.size:
            log.debug(f'check_for_padding[{checking_meta_directory.md_path}]: yield {unpack_parser.__class__} for {checking_meta_directory.file_path}')
            checking_meta_directory.unpack_parser = unpack_parser
            yield checking_meta_directory
        else:
            log.debug(f'check_for_padding[{checking_meta_directory.md_path}]: failed parse for {checking_meta_directory.file_path} with {unpack_parser.__class__} [{time.time_ns()}]')
            log.debug(f'check_for_padding[{checking_meta_directory.md_path}]: {checking_meta_directory.file_path} is not a padding file')
    except UnpackParserException as e:
        log.debug(f'check_for_padding[{checking_meta_directory.md_path}]: {unpack_parser.__class__} parser exception: {e}')

#####
# Computes and write a TLSH hash to the meta_directory
#
def compute_tlsh_hash(scan_environment, checking_meta_directory):
    try:
        if scan_environment.tlsh_minimum <= checking_meta_directory.size <= scan_environment.tlsh_maximum:
            labels = checking_meta_directory.info.get('labels', [])
            if scan_environment.tlsh_ignore.intersection(labels) == set():
                unpack_parser = TlshParser(checking_meta_directory, 0, scan_environment.configuration)
                log.debug(f'compute_tlsh_hash[{checking_meta_directory.md_path}]: trying parse for {checking_meta_directory.file_path} with {unpack_parser.__class__} [{time.time_ns()}]')

                checking_meta_directory.unpack_parser = unpack_parser
                unpack_parser.parse_from_offset()
                log.debug(f'compute_tlsh_hash[{checking_meta_directory.md_path}]: successful parse for {checking_meta_directory.file_path} with {unpack_parser.__class__} [{time.time_ns()}]')
                log.debug(f'compute_tlsh_hash[{checking_meta_directory.md_path}]: parsed_size = {unpack_parser.parsed_size}/{checking_meta_directory.size}')
                yield checking_meta_directory

    except UnpackParserException:
        # there will be a "parser resulted in zero length file"
        # warning, but ignore that.
        pass

#####
# Extracts strings from binaries and writes to the meta_directory
#
def extract_strings(scan_environment, checking_meta_directory):
    try:
        labels = checking_meta_directory.info.get('labels', [])
        if not labels:
            unpack_parser = StringExtractingParser(checking_meta_directory, 0, scan_environment.configuration)
            log.debug(f'extract_strings[{checking_meta_directory.md_path}]: trying parse for {checking_meta_directory.file_path} with {unpack_parser.__class__} [{time.time_ns()}]')

            checking_meta_directory.unpack_parser = unpack_parser
            unpack_parser.parse_from_offset()
            log.debug(f'extract_strings[{checking_meta_directory.md_path}]: successful parse for {checking_meta_directory.file_path} with {unpack_parser.__class__} [{time.time_ns()}]')
            log.debug(f'extract_strings[{checking_meta_directory.md_path}]: parsed_size = {unpack_parser.parsed_size}/{checking_meta_directory.size}')
            yield checking_meta_directory

    except UnpackParserException:
        # there will be a "parser resulted in zero length file"
        # warning, but ignore that.
        pass

#####
#
# Iterator that yields all combinations of extensions and UnpackParsers.
# We cannot do a direct lookup, since we do not know the extension in advance, for example
# file.tar.gz could have extension .gz, but also .tar.gz. Therefore we sacrifice a little
# speed to be more flexible.
#
def find_extension_parsers(scan_environment):
    log.debug(f'{scan_environment.parsers.unpackparsers_for_extensions}')
    for ext, unpack_parsers in scan_environment.parsers.unpackparsers_for_extensions.items():
        for unpack_parser_cls in unpack_parsers:
            #log.debug(f'find_extension_parser: {ext!r} parsed by {unpack_parser_cls}')
            yield ext, unpack_parser_cls

def check_with_suggested_parsers(scan_environment, checking_meta_directory):
    for unpack_parser_cls in ( scan_environment.parsers.get(p) for p in checking_meta_directory.info.get('suggested_parsers',[]) ):
        if unpack_parser_cls is None:
            continue

        try:
            unpack_parser = unpack_parser_cls(checking_meta_directory, 0, scan_environment.configuration)
            log.debug(f'check_with_suggested_parsers[{checking_meta_directory.md_path}]: trying parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
            unpack_parser.parse_from_offset()
            log.debug(f'check_with_suggested_parsers[{checking_meta_directory.md_path}]: successful parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
            if unpack_parser.parsed_size == checking_meta_directory.size:
                log.debug(f'check_with_suggested_parsers[{checking_meta_directory.md_path}]: parser parsed entire file')
                checking_meta_directory.unpack_parser = unpack_parser
                yield checking_meta_directory
            else:
                log.debug(f'check_with_suggested_parsers[{checking_meta_directory.md_path}]: parser parsed [0:{unpack_parser.parsed_size}], leaving [{unpack_parser.parsed_size}:{checking_meta_directory.size}] ({checking_meta_directory.size - unpack_parser.parsed_size} bytes)')
                # yield the checking_meta_directory with a ExtractingUnpackParser,
                # in case we want to record metadata about it.
                checking_meta_directory.unpack_parser = ExtractingParser.with_parts(
                    checking_meta_directory,
                    [ (0,unpack_parser.parsed_size),
                    (unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size) ],
                    scan_environment.configuration
                    )
                yield checking_meta_directory

                # yield the matched part of the file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, 0, unpack_parser.parsed_size)
                extracted_md.unpack_parser = unpack_parser
                with extracted_md.open() as md:
                    hashes = compute_hashes(md.open_file)
                    metadata = {'hashes': hashes}
                    md.info.setdefault('metadata', metadata)
                yield extracted_md

                # yield a synthesized file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
                extracted_md.unpack_parser = ExtractedParser.with_size(checking_meta_directory, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size, scan_environment.configuration)
                with extracted_md.open() as md:
                    hashes = compute_hashes(md.open_file)
                    metadata = {'hashes': hashes}
                    md.info.setdefault('metadata', metadata)
                yield extracted_md

        except UnpackParserException as e:
            log.debug(f'check_with_suggested_parsers[{checking_meta_directory.md_path}]: failed parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
            log.debug(f'check_with_suggested_parsers[{checking_meta_directory.md_path}]: {unpack_parser_cls} parser exception: {e}')

#####
#
# Iterator that yields a MetaDirectory for a successfully parsed file by extension.
# If the file contains extra data, it will yield MetaDirectory objects for the parent
# (i.e. checking_meta_directory), for the parsed part, and for the extracted part.
# Stops after a successful parse.
#
def check_by_extension(scan_environment, checking_meta_directory):
    for ext, unpack_parser_cls in find_extension_parsers(scan_environment):
        if matches_file_pattern(checking_meta_directory.file_path, ext):
            log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: {unpack_parser_cls} parses extension {ext} in {checking_meta_directory.file_path}')
            try:
                unpack_parser = unpack_parser_cls(checking_meta_directory, 0, scan_environment.configuration)
                log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: trying parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
                unpack_parser.parse_from_offset()
                log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: successful parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
                if unpack_parser.parsed_size == checking_meta_directory.size:
                    log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: parser parsed entire file')
                    checking_meta_directory.unpack_parser = unpack_parser
                    yield checking_meta_directory

                    # stop after first successful extension parse
                    return

                log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: parser parsed [0:{unpack_parser.parsed_size}], leaving [{unpack_parser.parsed_size}:{checking_meta_directory.size}] ({checking_meta_directory.size - unpack_parser.parsed_size} bytes)')
                # yield the checking_meta_directory with a ExtractingUnpackParser,
                # in case we want to record metadata about it.
                checking_meta_directory.unpack_parser = ExtractingParser.with_parts(
                    checking_meta_directory,
                    [ (0,unpack_parser.parsed_size),
                    (unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size) ],
                    scan_environment.configuration
                    )
                yield checking_meta_directory

                # yield the matched part of the file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, 0, unpack_parser.parsed_size)
                extracted_md.unpack_parser = unpack_parser
                with extracted_md.open() as md:
                    hashes = compute_hashes(md.open_file)
                    metadata = {'hashes': hashes}
                    md.info.setdefault('metadata', metadata)
                yield extracted_md

                # yield a synthesized file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
                extracted_md.unpack_parser = ExtractedParser.with_size(checking_meta_directory, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size, scan_environment.configuration)
                with extracted_md.open() as md:
                    hashes = compute_hashes(md.open_file)
                    metadata = {'hashes': hashes}
                    md.info.setdefault('metadata', metadata)
                yield extracted_md

                # stop after first successful extension parse
                # TODO: make this configurable?
                return

            except UnpackParserException as e:
                log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: failed parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
                log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: {unpack_parser_cls} parser exception: {e}')


@dataclass
class FileScanState:
    scanned_until: int
    chunk_start: int

#####
#
# Iterator that yields all combinations of offsets and UnpackParsers for all
# signatures found in open_file.
#
# Some caveats: not all signatures start at position 0 so offsets sometimes
# need to be corrected, for example ISO9660, ext2 and others. This could lead
# to a situation where the automaton finds a match, but there is another
# signature a bit further in the file that needs to be corrected and the
# corrected offset would be earlier than the found match. This is why matches
# cannot be just yielded when found, but need to be sorted after applying any
# offset corrections. For this the chunk size should minimally be the largest
# correction + the length of the signature.
#
# Even though the above method will largely mitigate this issue there is a
# chance that a few offsets will be reported even though after correction
# earlier offsets will be found. The only way to prevent this is to set the
# chunk size to the size of the largest file that will be scanned.
#
# Polyglot files (where one file could be different valid files depending on
# how the file is read (random access, from the front, etc.) could lead to
# the same offset reported for multiple parsers. To choose the right parser
# the parsers are sorted by priority, with priorities being declared in the
# UnpackParser.py file (default: 0 - no priority).
#
def find_signature_parsers(scan_environment, open_file, file_scan_state, file_size):
    '''Yield all matching signatures'''
    file_scan_state.chunk_start = file_scan_state.scanned_until
    chunk_size = scan_environment.signature_chunk_size
    chunk_overlap = scan_environment.parsers.longest_signature_length - 1
    while file_scan_state.chunk_start < file_size:
        open_file.seek(file_scan_state.chunk_start)
        s = open_file.read(chunk_size)
        #log.debug(f'find_signature_parsers: read [{file_scan_state.chunk_start}:+{len(s)}]')

        # store the parsers found so far instead of yielding every found
        # parser as the offset possibly needs to be corrected because
        # the signature doesn't appear at the start of the file
        # (examples: MBR, ISO9660).
        found_parsers = {}
        for end_index, (end_difference, unpack_parser_cls) in scan_environment.parsers.automaton.iter(s):
            offset = file_scan_state.chunk_start + end_index - end_difference
            #log.debug(f'find_signature_parsers: got match at [{offset}:{file_scan_state.chunk_start+end_index}]')
            if offset < file_scan_state.scanned_until:
                #log.debug(f'find_signature_parsers: {offset=} < {file_scan_state.scanned_until=}')
                pass
            elif file_scan_state.chunk_start > file_scan_state.scanned_until and end_index < chunk_overlap:
                #log.debug(f'find_signature_parsers: match falls within overlap: {end_index=} < {chunk_overlap=}')
                pass
            else:
                if offset not in found_parsers:
                    found_parsers[offset] = []
                found_parsers[offset] += unpack_parser_cls

        # sort the parsers found based on offsets
        for offset in sorted(found_parsers):
            # sort the parsers found at each offset based on priority
            yield offset, sorted(found_parsers[offset], key=lambda x: x.priority, reverse=True)

        if file_scan_state.chunk_start + len(s) >= file_size:
            # this was the last chunk
            file_scan_state.chunk_start += len(s)
        else:
            # set chunk_start to before the actual chunk to
            # detect overlapping patterns in the next chunk
            file_scan_state.chunk_start += len(s) - chunk_overlap

        # unless the unpackparser advanced us
        file_scan_state.chunk_start = max(file_scan_state.chunk_start, file_scan_state.scanned_until)

#####
#
# Iterator that yields succesfully parsed parts in meta_directory.open_file and the parts
# that are not parsed, in order. It chooses the first signature that it parses successfully,
# and will not yield any overlapping results.
#
def scan_signatures(scan_environment, meta_directory):
    '''Iterator that yields succesfully parsed parts'''
    file_scan_state = FileScanState(0,0)
    for offset, unpack_parser_classes in find_signature_parsers(scan_environment, meta_directory.open_file, file_scan_state, meta_directory.size):
        log.debug(f'scan_signatures[{meta_directory.md_path}]: wait at {file_scan_state.scanned_until}, found parsers at {offset}: {unpack_parser_classes}')
        if offset < file_scan_state.scanned_until: # we have passed this point in the file, ignore the result
            log.debug(f'scan_signatures[{meta_directory.md_path}]: skipping [{offset}:{file_scan_state.scanned_until}]')
            continue

        for unpack_parser_cls in unpack_parser_classes:
            # try if the unpackparser works
            try:
                unpack_parser = unpack_parser_cls(meta_directory, offset, scan_environment.configuration)
                log.debug(f'scan_signatures[{meta_directory.md_path}]: trying parse at {meta_directory.file_path}:{offset} with {unpack_parser_cls} [{time.time_ns()}]')
                unpack_parser.parse_from_offset()
                log.debug(f'scan_signatures[{meta_directory.md_path}]: successful parse at {meta_directory.file_path}:{offset} with {unpack_parser_cls} [{time.time_ns()}]')
                if offset == 0 and unpack_parser.parsed_size == meta_directory.size:
                    log.debug(f'scan_signatures[{meta_directory.md_path}]: skipping [{file_scan_state.scanned_until}:{unpack_parser.parsed_size}], covers entire file, yielding {unpack_parser_cls} and return')
                    yield 0, unpack_parser
                    return

                if offset > file_scan_state.scanned_until:
                    # if it does, yield a synthesizing parser for the padding before the file
                    log.debug(f'scan_signatures[{meta_directory.md_path}]: [{file_scan_state.scanned_until}:{offset}] yields SynthesizingParser, length {offset - file_scan_state.scanned_until}')
                    yield file_scan_state.scanned_until, SynthesizingParser.with_size(meta_directory, offset, offset - file_scan_state.scanned_until, scan_environment.configuration)

                # yield the part that the unpackparser parsed
                log.debug(f'scan_signatures[{meta_directory.md_path}]: [{offset}:{offset+unpack_parser.parsed_size}] yields {unpack_parser_cls}, length {unpack_parser.parsed_size}')
                yield offset, unpack_parser
                file_scan_state.scanned_until = offset + unpack_parser.parsed_size
            except UnpackParserException as e:
                log.debug(f'scan_signatures[{meta_directory.md_path}]: failed parse at {meta_directory.file_path}:{offset} with {unpack_parser_cls} [{time.time_ns()}]')
                log.debug(f'scan_signatures[{meta_directory.md_path}]: {unpack_parser_cls} parser exception: {e}')

    # yield the trailing part that could not be parsed
    if 0 < file_scan_state.scanned_until < meta_directory.size:
        log.debug(f'scan_signatures[{meta_directory.md_path}]: [{file_scan_state.scanned_until}:{meta_directory.size}] yields SynthesizingParser, length {meta_directory.size - file_scan_state.scanned_until}')
        yield file_scan_state.scanned_until, SynthesizingParser.with_size(meta_directory, offset, meta_directory.size - file_scan_state.scanned_until, scan_environment.configuration)


#####
#
# Iterator that yields a MetaDirectory for all file parts parsed by signature. If the
# file itself is the only part, it will yield checking_meta_directory, otherwise,
# it will yield MetaDirectory objects for the parent (i.e. checking_meta_directory),
# and for all the parsed and extracted parts.
#
def check_by_signature(scan_environment, checking_meta_directory):
    '''Find signature offsets'''
    parts = [] # record the parts for the ExtractingParser
    for offset, unpack_parser in scan_signatures(scan_environment, checking_meta_directory):
        log.debug(f'check_by_signature[{checking_meta_directory.md_path}]check_by_signature: got match at {offset}: {unpack_parser.__class__} length {unpack_parser.parsed_size}')
        if offset == 0 and unpack_parser.parsed_size == checking_meta_directory.size:
            # no need to extract a subfile
            checking_meta_directory.unpack_parser = unpack_parser
            yield checking_meta_directory
        else:
            extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, offset, unpack_parser.parsed_size)
            extracted_md.unpack_parser = unpack_parser
            with extracted_md.open() as md:
                hashes = compute_hashes(md.open_file)
                metadata = {'hashes': hashes}
                md.info.setdefault('metadata', metadata)
            yield extracted_md
            parts.append((offset, unpack_parser.parsed_size))

    # yield ExtractingParser
    if parts:
        checking_meta_directory.unpack_parser = ExtractingParser.with_parts(checking_meta_directory, parts, scan_environment.configuration)
        yield checking_meta_directory

def check_featureless(scan_environment, checking_meta_directory):
    for unpack_parser_cls in scan_environment.parsers.unpackparsers_for_featureless_files:
        log.debug(f'check_featureless[{checking_meta_directory.md_path}]: {unpack_parser_cls}')
        try:
            unpack_parser = unpack_parser_cls(checking_meta_directory, 0, scan_environment.configuration)
            log.debug(f'check_featureless[{checking_meta_directory.md_path}]: trying parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
            unpack_parser.parse_from_offset()
            log.debug(f'check_featureless[{checking_meta_directory.md_path}]: successful parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
            if unpack_parser.parsed_size == checking_meta_directory.size:
                log.debug(f'check_featureless[{checking_meta_directory.md_path}]: parser parsed entire file')
                checking_meta_directory.unpack_parser = unpack_parser
                yield checking_meta_directory
            else:
                log.debug(f'check_featureless[{checking_meta_directory.md_path}]: parser parsed [0:{unpack_parser.parsed_size}], leaving [{unpack_parser.parsed_size}:{checking_meta_directory.size - unpack_parser.parsed_size} bytes')
                # yield the checking_meta_directory with a ExtractingUnpackParser, in
                # case we want to record metadata about it.
                checking_meta_directory.unpack_parser = ExtractingParser.with_parts(
                    checking_meta_directory,
                    [ (0,unpack_parser.parsed_size),
                    (unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size) ],
                    scan_environment.configuration
                    )
                yield checking_meta_directory

                # yield the matched part of the file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, 0, unpack_parser.parsed_size)
                extracted_md.unpack_parser = unpack_parser
                with extracted_md.open() as md:
                    hashes = compute_hashes(md.open_file)
                    metadata = {'hashes': hashes}
                    md.info.setdefault('metadata', metadata)
                yield extracted_md

                # yield a synthesized file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
                extracted_md.unpack_parser = ExtractedParser.with_size(checking_meta_directory, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size, scan_environment.configuration)
                with extracted_md.open() as md:
                    hashes = compute_hashes(md.open_file)
                    metadata = {'hashes': hashes}
                    md.info.setdefault('metadata', metadata)
                yield extracted_md

                # stop after first successful extension parse
                # TODO: make this configurable?
                return

        except UnpackParserException as e:
            log.debug(f'check_featureless[{checking_meta_directory.md_path}]: failed parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
            log.debug(f'check_featureless[{checking_meta_directory.md_path}]: {unpack_parser_cls} parser exception: {e}')

#####
#
# Pipelines: dynamically create a series of steps in the scanning or analysis.
#
# A pipe is a function that for a scan_environment and meta_directory, does something
# and returns a boolean that indicates whether we should continue (True = continue,
# False = stop).
#

def cond_scannable(scan_environment, meta_directory):
    return is_scannable(meta_directory.file_path)

def cond_not_synthesized(scan_environment, meta_directory):
    '''returns whether a file is NOT synthesized.'''
    return 'synthesize' not in meta_directory.info.get('labels',[])

def cond_if_scanned(scan_environment, meta_directory):
    return meta_directory.is_scanned()

def xstop_if_scanned(scan_environment, meta_directory):
    '''this pipe tells the pipeline to stop if the meta_directory is scanned.'''
    # equivalent to pipe_cond(cond_if_scanned, pipe_fail, pipe_pass)
    return not meta_directory.is_scanned()

#####
#
# The checking_iterator is an iterator: for every positive check result, it yields a
# MetaDirectory (could be the one for the current file, or could be one that is
# extracted, if the file contains multiple parts).
#
# This MetaDirectory object has an unpack_parser property, which this pipe will use to
# write metadata to the MetaDirectory.
# There are special parsers for parts that could not be recognized (SynthesizingParser
# and ExtractedParser), for padding files (PaddingParser), and for a file from which
# files are extracted (ExtractingParser).
#
# This pipe will also call the UnpackParser to unpack any files (for example for archives).
# The UnpackParser's unpack method will unpack the files into the MetaDirectory, and yield
# a MetaDirectory object for every unpacked file. The code will create a new ScanJob for each
# unpacked MetaDirectory and queue it.
#
def pipe_exec(checking_iterator):
    '''this pipe runs checking_iterator on the scan_environment and meta_directory.'''
    def _check(scan_environment, meta_directory):
        for md in checking_iterator(scan_environment, meta_directory):
            log.debug(f'pipe_exec({checking_iterator})[{meta_directory.md_path}]: analyzing {md.file_path} into {md.md_path} with {md.unpack_parser.__class__} [{time.time_ns()}]')

            with md.open(open_file=False):
                # write metadata for the parser
                md.write_info_with_unpack_parser()
                log.debug(f'pipe_exec({checking_iterator})[{meta_directory.md_path}]: unpacking {md.file_path} into {md.md_path} with {md.unpack_parser.__class__} [{time.time_ns()}]')

                # try to unpack files (if any)
                for unpacked_md in md.unpack_with_unpack_parser():
                    log.debug(f'pipe_exec({checking_iterator})[{meta_directory.md_path}]: queue unpacked file {unpacked_md.md_path}')

                    # create a new job for the unpacked file and queue it
                    job = ScanJob(unpacked_md.md_path)
                    scan_environment.scan_queue.put(job)

                    # wake up all waiting threads as there is new data in the queue
                    scan_environment.barrier.reset()
                    log.debug(f'pipe_exec({checking_iterator})[{meta_directory.md_path}]: queued job [{time.time_ns()}]')
                log.debug(f'pipe_exec({checking_iterator})[{meta_directory.md_path}]: unpacked {md.file_path} into {md.md_path} with {md.unpack_parser.__class__} [{time.time_ns()}]')
        return True
    return _check

def pipe_pass(scan_environment, meta_directory):
    '''this pipe does nothing.'''
    return True

def pipe_fail(scan_environment, meta_directory):
    '''this pipe makes the pipeline stop.'''
    return False

def pipe_cond(predicate, pipe_if_true, pipe_if_false):
    '''conditional pipe: runs pipe_if_true if predicate is true on
       scan_environment and meta_directory, and pipe_if_false otherwise.
    '''
    def _check(scan_environment, meta_directory):
        if predicate(scan_environment, meta_directory):
            return pipe_if_true(scan_environment, meta_directory)
        return pipe_if_false(scan_environment, meta_directory)
    return _check

def pipe_seq(*pipes):
    '''run a series of pipes until one fails.'''
    def _check(scan_environment, meta_directory):
        for pipe in pipes:
            log.debug(f'pipe_seq: running {pipe}')
            r = pipe(scan_environment, meta_directory)
            log.debug(f'pipe_seq: {pipe} returned {r}')
            if not r:
                return r
        return True
    return _check

def pipe_or(*pipes):
    '''run all pipes in pipes and keep running even if one succeeds.'''
    def _check(scan_environment, meta_directory):
        result = False
        for pipe in pipes:
            log.debug(f'pipe_or: running {pipe}')
            r = pipe(scan_environment, meta_directory)
            log.debug(f'pipe_or: {pipe} returned {r}')
            result = result or r
        return result
    return _check

def pipe_not(pipe):
    '''run a pipe, and stop if it passed.'''
    def _check(scan_environment, meta_directory):
        log.debug(f'pipe_not: running {pipe}')
        r = pipe(scan_environment, meta_directory)
        log.debug(f'pipe_not: {pipe} returned {r}')
        return not r
    return _check

def ctx_open_md_for_writing(scan_environment, meta_directory):
    return meta_directory.open()

def ctx_open_md_for_updating(scan_environment, meta_directory):
    return meta_directory.open(open_file=False)

def ctx_open_md_readonly(scan_environment, meta_directory):
    return meta_directory.open(open_file=False, info_write=False)

def pipe_with(context, pipe):
    def _check(scan_environment, meta_directory):
        with context(scan_environment, meta_directory):
            return pipe(scan_environment, meta_directory)
    return _check

#####
#
# Pipeline for scanning files.
#

def make_scan_pipeline():
    '''Helper function to create scan pipelines'''
    stop_if_scanned = pipe_cond(cond_if_scanned, pipe_fail, pipe_pass)

    pipe_padding = pipe_seq(pipe_exec(check_for_padding), stop_if_scanned)

    pipe_hashes = pipe_exec(compute_tlsh_hash)
    pipe_strings = pipe_exec(extract_strings)

    pipe_checks_if_not_synthesized = pipe_cond(
            cond_not_synthesized,
            pipe_seq(
                pipe_exec(check_by_extension), stop_if_scanned,
                pipe_exec(check_by_signature), stop_if_scanned
            ),
            pipe_pass
        )

    pipe_scan = pipe_seq(
            pipe_exec(check_with_suggested_parsers), stop_if_scanned,
            pipe_padding, stop_if_scanned,
            pipe_checks_if_not_synthesized,
            pipe_exec(check_featureless)
        )

    # TODO: if we want to record meta data for unscannable files,
    # make sure to add a pipe_with to open the meta_directory with open_file=False.
    pipe_root = pipe_or(pipe_cond(
        cond_scannable,
        pipe_with(ctx_open_md_for_writing, pipe_scan),
        pipe_fail), pipe_with(ctx_open_md_for_writing, pipe_strings)
        #pipe_fail), pipe_with(ctx_open_md_for_writing, pipe_hashes)
    )
    return pipe_root

# Example: resume scan:
# pipe_seq(
#   pipe_with(ctx_open_md_readonly,
#     pipe_cond(cond_if_scanned, pipe_queue_subfiles, pipe_pass),
#   ),
#   stop_if_scanned,
#   pipe_root
# )

# Example: scan file, and if scanned, run analysis pipeline:
# pipe_or( pipe_with(ctx_open_md_for_writing, pipe_scan), pipe_cond(cond_if_scanned, pipe_with(ctx_open_md_for_updating, pipe_analysis), pipe_fail) )
# pipe_seq( pipe_with(ctx_open_md_for_writing, pipe_scan), stop_if_not_scanned, pipe_with(ctx_open_md_for_updating, pipe_analysis) )
# pipe_seq( pipe_with(ctx_open_md_for_writing, pipe_scan), pipe_not(stop_if_scanned), pipe_with(ctx_open_md_for_updating, pipe_analysis) )


#####
#
# Process all jobs on the scan queue in the scan_environment.
# The scanjob stores a MetaDirectory path that contains all information needed for
# processing, such as the path of the file to analyze, and any context.
#
def process_jobs(pipeline, scan_environment):
    # TODO: code smell, should not be needed if unpackparsers behave
    current_dir = os.getcwd()
    os.chdir(scan_environment.unpack_directory)

    while True:
        log.debug('process_jobs: getting scanjob')

        try:
            # grab a job from the queue
            scanjob = scan_environment.scan_queue.get(timeout=scan_environment.job_wait_time)
            log.debug(f'process_jobs: {scanjob=}')

            scanjob.scan_environment = scan_environment
            log.debug(f'process_jobs[{scanjob.meta_directory.md_path}]: start job [{time.time_ns()}]')

            # first compute some checksums here, so files that should be
            # ignored actually can be ignored. Note: these are the checksums
            # for the *entire* file, not for parts that have been unpacked and
            # carved which are (to be) computed somewhere else.
            with scanjob.meta_directory.open() as md:
                hashes = compute_hashes(md.open_file)
                metadata = {'hashes': hashes}
                scanjob.meta_directory.info.setdefault('metadata', metadata)

                if hashes['sha256'] in scan_environment.ignore:
                    labels = ['ignored']
                    scanjob.meta_directory.info.setdefault('labels', labels)
                    continue

            # start the pipeline for the job
            pipeline(scanjob.scan_environment, scanjob.meta_directory)

            log.debug(f'process_jobs[{scanjob.meta_directory.md_path}]: end job [{time.time_ns()}]')
        except queue.Empty:
            log.debug('process_jobs: scan queue is empty')
            try:
                # A thread will block here and wait until either *all*
                # threads end up here (meaning the program is done)
                # or wait for new data to arrive in the scanning queue.
                scan_environment.barrier.wait()
                log.debug('process_jobs: all scanjobs are waiting')
                break
            except threading.BrokenBarrierError:
                # all waiting threads are woken up again here
                # because there is new data in the scanning queue
                continue
        except Exception as e:
            log.error(f'process_jobs: caught exception {e}')
            exc_type, exc_value, exc_traceback = sys.exc_info()
            exc_trace = traceback.format_exception(exc_type, exc_value, exc_traceback)
            log.error(f'process_jobs:\n{"".join(exc_trace)}')
            break
    log.debug('process_jobs: exiting')

    # TODO: this should not be needed if unpackparsers behave
    os.chdir(current_dir)

def matches_file_pattern(filename, extension):
    '''checks whether a file ends in the string extension (case insensitive).'''
    return filename.name.lower().endswith(extension)
