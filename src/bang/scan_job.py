import os
import re
import sys
import traceback
import time
import queue
import multiprocessing
from dataclasses import dataclass
from operator import itemgetter
from .meta_directory import *
from .UnpackParser import SynthesizingParser, ExtractingParser, PaddingParser
from .UnpackParserException import UnpackParserException
from bang import signatures
from .log import log

class ScanJob:
    def __init__(self, path):
        self._path = path
        self._meta_directory = None
        self._scan_environment = None

    @property
    def scan_environment(self):
        return self._scan_environment

    @scan_environment.setter
    def scan_environment(self, scan_environment):
        self._scan_environment = scan_environment

    @property
    def meta_directory(self):
        if self._meta_directory is None:
            self._meta_directory = MetaDirectory.from_md_path(self.scan_environment.unpackdirectory, self._path)
        return self._meta_directory

#####
#
# Returns if a path is an unscannable file, i.e. not a regular file or empty.
#
def is_unscannable(path):
    # TODO: do we want labels on unscannable files?
    return not path.is_file() or path.stat().st_size == 0
    # return path.is_dir() or path.is_fifo() or path.is_socket() or path.is_block_device() or path.is_char_device() or path.is_symlink()


#####
#
# Extracts in_file[offset:offset+file_size] in checking_meta_directory.
#
def extract_file(checking_meta_directory, in_file, offset, file_size):
    # TODO: check if offset and file_size parameters are still needed in next line
    with checking_meta_directory.extract_file(offset, file_size) as (extracted_md, extracted_file):
        os.sendfile(extracted_file.fileno(), in_file.fileno(), offset, file_size)
    return extracted_md

#####
#
# Iterator that checks if the file for checking_meta_directory is a padding file. Yields
# checking_meta_directory if this is the case.
#
def check_for_padding(scan_environment, checking_meta_directory):
    try:
        unpack_parser = PaddingParser(checking_meta_directory, 0)
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

#####
#
# Iterator that yields a MetaDirectory for a successfully parsed file by extension. If the
# file contains extra data, it will yield MetaDirectory objects for the parent
# (i.e. checking_meta_directory), for the parsed part, and for the extracted part.
# Stops after a successful parse.
#
def check_by_extension(scan_environment, checking_meta_directory):
    for ext, unpack_parser_cls in find_extension_parsers(scan_environment):
        if signatures.matches_file_pattern(checking_meta_directory.file_path, ext):
            log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: {unpack_parser_cls} parses extension {ext} in {checking_meta_directory.file_path}')
            try:
                unpack_parser = unpack_parser_cls(checking_meta_directory, 0)
                log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: trying parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
                unpack_parser.parse_from_offset()
                log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: successful parse for {checking_meta_directory.file_path} with {unpack_parser_cls} [{time.time_ns()}]')
                if unpack_parser.parsed_size == checking_meta_directory.size:
                    log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: parser parsed entire file')
                    checking_meta_directory.unpack_parser = unpack_parser
                    yield checking_meta_directory
                else:
                    log.debug(f'check_by_extension[{checking_meta_directory.md_path}]: parser parsed [0:{unpack_parser.parsed_size}], leaving [{unpack_parser.parsed_size}:{checking_meta_directory.size}] ({checking_meta_directory.size - unpack_parser.parsed_size} bytes)')
                    # yield the checking_meta_directory with a ExtractingUnpackParser, in
                    # case we want to record metadata about it.
                    checking_meta_directory.unpack_parser = ExtractingParser.with_parts(
                        checking_meta_directory,
                        [ (0,unpack_parser.parsed_size),
                        (unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size) ]
                        )
                    yield checking_meta_directory

                    # yield the matched part of the file
                    extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, 0, unpack_parser.parsed_size)
                    extracted_md.unpack_parser = unpack_parser
                    yield extracted_md

                    # yield a synthesized file
                    extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
                    extracted_md.unpack_parser = ExtractedParser.with_size(checking_meta_directory, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
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
# Iterator that yields all combinations of offsets and UnpackParsers for all signatures
# found in open_file.
#
def find_signature_parsers(scan_environment, open_file, file_scan_state, file_size):
    # yield all matching signatures
    file_scan_state.chunk_start = file_scan_state.scanned_until
    chunk_size = scan_environment.signature_chunk_size
    chunk_overlap = scan_environment.parsers.longest_signature_length - 1
    while file_scan_state.chunk_start < file_size:
        open_file.seek(file_scan_state.chunk_start)
        s = open_file.read(chunk_size)
        #log.debug(f'find_signature_parsers: read [{file_scan_state.chunk_start}:+{len(s)}]')
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
                yield offset, unpack_parser_cls
        if file_scan_state.chunk_start + len(s) >= file_size:
            # this was the last chunk
            file_scan_state.chunk_start += len(s)
        else:
            # set chunk_start to before the actual chunk to detect overlapping patterns in the next chunk
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
    file_scan_state = FileScanState(0,0)
    for offset, unpack_parser_cls in find_signature_parsers(scan_environment, meta_directory.open_file, file_scan_state, meta_directory.size):
        log.debug(f'scan_signatures[{meta_directory.md_path}]: wait at {file_scan_state.scanned_until}, found parser at {offset}: {unpack_parser_cls}')
        if offset < file_scan_state.scanned_until: # we have passed this point in the file, ignore the result
            log.debug(f'scan_signatures[{meta_directory.md_path}]: skipping [{offset}:{file_scan_state.scanned_until}]')
            continue
        # try if the unpackparser works
        try:
            unpack_parser = unpack_parser_cls(meta_directory, offset)
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
                yield file_scan_state.scanned_until, SynthesizingParser.with_size(meta_directory, offset, offset - file_scan_state.scanned_until)
            # yield the part that the unpackparser parsed
            log.debug(f'scan_signatures[{meta_directory.md_path}]: [{offset}:{offset+unpack_parser.parsed_size}] yields {unpack_parser_cls}, length {unpack_parser.parsed_size}')
            yield offset, unpack_parser
            file_scan_state.scanned_until = offset + unpack_parser.parsed_size
        except UnpackParserException as e:
            log.debug(f'scan_signatures[{meta_directory.md_path}]: failed parse at {meta_directory.file_path}:{offset} with {unpack_parser_cls} [{time.time_ns()}]')
            log.debug(f'scan_signatures[{meta_directory.md_path}]: {unpack_parser_cls} parser exception: {e}')
    # yield the trailing part
    if 0 < file_scan_state.scanned_until < meta_directory.size:
        log.debug(f'scan_signatures[{meta_directory.md_path}]: [{file_scan_state.scanned_until}:{meta_directory.size}] yields SynthesizingParser, length {meta_directory.size - file_scan_state.scanned_until}')
        yield file_scan_state.scanned_until, SynthesizingParser.with_size(meta_directory, offset, meta_directory.size - file_scan_state.scanned_until)


#####
#
# Iterator that yields a MetaDirectory for all file parts parsed by signature. If the
# file itself is the only part, it will yield checking_meta_directory, otherwise,
# it will yield MetaDirectory objects for the parent (i.e. checking_meta_directory), and
# for all the parsed and extracted parts.
#
def check_by_signature(scan_environment, checking_meta_directory):
    # find offsets
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
            yield extracted_md
            parts.append((offset, unpack_parser.parsed_size))
        # yield ExtractingParser
        if parts != []:
            checking_meta_directory.unpack_parser = ExtractingParser.with_parts(checking_meta_directory, parts)
            yield checking_meta_directory

def check_featureless(scan_environment, checking_meta_directory):
    for unpack_parser_cls in scan_environment.parsers.unpackparsers_for_featureless_files:
        log.debug(f'check_featureless[{checking_meta_directory.md_path}]: {unpack_parser_cls}')
        try:
            unpack_parser = unpack_parser_cls(checking_meta_directory, 0)
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
                    (unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size) ]
                    )
                yield checking_meta_directory

                # yield the matched part of the file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, 0, unpack_parser.parsed_size)
                extracted_md.unpack_parser = unpack_parser
                yield extracted_md

                # yield a synthesized file
                extracted_md = extract_file(checking_meta_directory, checking_meta_directory.open_file, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
                extracted_md.unpack_parser = ExtractedParser.with_size(checking_meta_directory, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
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
# and returns a boolean that indicates whether we should stop (True = stop,
# False = continue).
#

def cond_unscannable(scan_environment, meta_directory):
    return is_unscannable(meta_directory.file_path)

def cond_not_synthesized(scan_environment, meta_directory):
    '''returns whether a file is NOT synthesized.'''
    return 'synthesize' not in meta_directory.info.get('labels',[])

def stop_if_scanned(scan_environment, meta_directory):
    '''this pipe tells the pipeline to stop if the meta_directory is scanned.'''
    return meta_directory.is_scanned()

def pipe_iter(checking_iterator):
    '''this pipe runs checking_iterator on the scan_environment and meta_directory.'''
    def _check(scan_environment, meta_directory):
        for md in checking_iterator(scan_environment, meta_directory):
            log.debug(f'pipe_iter({checking_iterator})[{meta_directory.md_path}]: analyzing {md.file_path} into {md.md_path} with {md.unpack_parser.__class__} [{time.time_ns()}]')
            with md.open(open_file=False):
                md.write_info_with_unpack_parser()
                log.debug(f'pipe_iter({checking_iterator})[{meta_directory.md_path}]: unpacking {md.file_path} into {md.md_path} with {md.unpack_parser.__class__} [{time.time_ns()}]')
                for unpacked_md in md.unpack_with_unpack_parser():
                    log.debug(f'pipe_iter({checking_iterator})[{meta_directory.md_path}]: queue unpacked file {unpacked_md.md_path}')
                    job = ScanJob(unpacked_md.md_path)
                    scan_environment.scan_queue.put(job)
                    log.debug(f'pipe_iter({checking_iterator})[{meta_directory.md_path}]: queued job [{time.time_ns()}]')
                log.debug(f'pipe_iter({checking_iterator})[{meta_directory.md_path}]: unpacked {md.file_path} into {md.md_path} with {md.unpack_parser.__class__} [{time.time_ns()}]')
        return False
    return _check

def pipe_pass():
    '''this pipe does nothing.'''
    def _check(scan_environment, meta_directory):
        return False
    return _check

def pipe_fail():
    '''this pipe makes the pipeline stop.'''
    def _check(scan_environment, meta_directory):
        return True
    return _check

def pipe_cond(predicate, pipe_if_true, pipe_if_false):
    '''conditional pipe: runs pipe_if_true if predicate is true on scan_environment and meta_directory,
    and pipe_if_false otherwise.
    '''
    def _check(scan_environment, meta_directory):
        if predicate(scan_environment, meta_directory):
            return pipe_if_true(scan_environment, meta_directory)
        else:
            return pipe_if_false(scan_environment, meta_directory)
    return _check

def pipe_seq(*pipes):
    '''run a series of pipes until we are told to stop.'''
    def _check(scan_environment, meta_directory):
        for pipe in pipes:
            log.debug(f'pipe_seq: running {pipe}')
            r = pipe(scan_environment, meta_directory)
            log.debug(f'pipe_seq: {pipe} returned {r}')
            if r:
                return r
        return False
    return _check

def pipe_with_open_md_for_writing(pipe):
    def _check(scan_environment, meta_directory):
        with meta_directory.open():
            return pipe(scan_environment, meta_directory)
    return _check

def make_scan_pipeline():
    pipe_padding = pipe_seq(pipe_iter(check_for_padding), stop_if_scanned)
    pipe_if_synthesized = pipe_cond(
            cond_not_synthesized,
            pipe_seq(
                pipe_iter(check_by_extension), stop_if_scanned,
                pipe_iter(check_by_signature), stop_if_scanned
            ),
            pipe_pass
        )
    pipe_scannable = pipe_seq(
            pipe_padding,
            pipe_if_synthesized,
            pipe_iter(check_featureless)
        )
    # TODO: if we want to record meta data for unscannable files,
    # make sure to add a pipe_with to open the meta_directory with open_file=False.
    pipe_root = pipe_cond(
        cond_unscannable,
        pipe_fail,
        pipe_with_open_md_for_writing(pipe_scannable)
    )
    return pipe_root

#####
#
# Processes a ScanJob. The scanjob stores a MetaDirectory path that contains all
# information needed for processing, such as the path of the file to analyze, and
# any context.
# (Most) checks follow the iterator pattern: for every positive check result, the code
# yields a MetaDirectory (could be the one for the current file, or could be one that is
# extracted, if the file contains multiple parts). This MetaDirectory object has an
# unpack_parser property, which the code will use to write metadata to this MetaDirectory.
# There are special parsers for parts that could not be parsed (SynthesizingParser), for
# padding files (PaddingParser), and for a file from which files are extracted
# (ExtractingParser).
# The code will also call the UnpackParser to unpack any files (for example for archives).
# The UnpackParser's unpack method will unpack the files into the MetaDirectory, and yield
# a MetaDirectory object for every unpacked file. The code will create a new ScanJob for each
# unpacked MetaDirectory and queue it.
#
def process_job(pipeline, scanjob):
    # scanjob has: path, meta_directory object and context
    meta_directory = scanjob.meta_directory
    log.debug(f'process_job[{scanjob.meta_directory.md_path}]: enter')
    pipeline(scanjob.scan_environment, meta_directory)


####
#
# Process all jobs on the scan queue in the scan_environment.
#
def process_jobs(pipeline, scan_environment):
    # TODO: code smell, should not be needed if unpackparsers behave
    current_dir = os.getcwd()
    os.chdir(scan_environment.unpackdirectory)

    while True:
        # TODO: check if timeout long enough
        log.debug(f'process_jobs: getting scanjob')
        s = scan_environment.scan_semaphore.acquire(blocking=False)
        if s == True: # at least one scan job is running
            try:
                #scanjob = scan_environment.scan_queue.get(timeout=86400)
                scanjob = scan_environment.scan_queue.get(timeout=scan_environment.job_wait_time)
                log.debug(f'process_jobs: {scanjob=}')
                scan_environment.scan_semaphore.release()
                scanjob.scan_environment = scan_environment
                log.debug(f'process_jobs[{scanjob.meta_directory.md_path}]: start job [{time.time_ns()}]')
                process_job(pipeline, scanjob)
                log.debug(f'process_jobs[{scanjob.meta_directory.md_path}]: end job [{time.time_ns()}]')
            except queue.Empty as e:
                log.debug(f'process_jobs: scan queue is empty')
            except Exception as e:
                log.error(f'process_jobs: caught exception {e}')
                exc_type, exc_value, exc_traceback = sys.exc_info()
                exc_trace = traceback.format_exception(exc_type, exc_value, exc_traceback)
                log.error(f'process_jobs:\n{"".join(exc_trace)}')
                scan_environment.scan_semaphore.acquire(blocking=False)
                break
        else: # all scanjobs are waiting
            log.debug(f'process_jobs: all scanjobs are waiting')
            break
    log.debug(f'process_jobs: exiting')
    # scan_environment.scan_queue.join()
    os.chdir(current_dir)

