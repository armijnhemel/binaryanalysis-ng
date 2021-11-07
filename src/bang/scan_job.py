import os
import re
import mmap
import queue
import logging
from operator import itemgetter
from .meta_directory import *
from .UnpackParser import SynthesizingParser, ExtractingParser, PaddingParser
from .UnpackParserException import UnpackParserException
import bang.bangsignatures

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
    with checking_meta_directory.extract_file(offset, file_size) as (extracted_md, extracted_file):
        os.sendfile(extracted_file.fileno(), in_file.fileno(), offset, file_size)
    return extracted_md

#####
#
# Iterator that checks if the file for checking_meta_directory is a padding file. Yields
# checking_meta_directory if this is the case.
#
def check_for_padding(checking_meta_directory):
    try:
        unpack_parser = PaddingParser(checking_meta_directory, 0)
        unpack_parser.parse_from_offset()
        logging.debug(f'[{checking_meta_directory.md_path}]check_for_padding: size = {unpack_parser.parsed_size}/{checking_meta_directory.size}')
        if unpack_parser.parsed_size == checking_meta_directory.size:
            logging.debug(f'[{checking_meta_directory.md_path}]check_for_padding: yield {unpack_parser} for {checking_meta_directory.file_path}')
            checking_meta_directory.unpack_parser = unpack_parser
            yield checking_meta_directory
    except UnpackParserException as e:
        logging.debug(f'[{checking_meta_directory.md_path}]check_for_padding: parser exception: {e}')

    logging.debug(f'[{checking_meta_directory.md_path}]check_for_padding: {checking_meta_directory.file_path} is not a padding file')

#####
#
# Iterator that yields all combinations of extensions and UnpackParsers.
# We cannot do a direct lookup, since we do not know the extension in advance, for example
# file.tar.gz could have extension .gz, but also .tar.gz. Therefore we sacrifice a little
# speed to be more flexible.
#
def find_extension_parsers(scan_environment):
    for ext, unpack_parsers in scan_environment.get_unpackparsers_for_extensions().items():
        for unpack_parser_cls in unpack_parsers:
            logging.debug(f'find_extension_parser: {ext!r} parsed by {unpack_parser_cls}')
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
        if bangsignatures.matches_file_pattern(checking_meta_directory.file_path, ext):
            logging.debug(f'[{checking_meta_directory.md_path}]check_by_extension: {unpack_parser_cls} parses extension {ext}')
            try:
                unpack_parser = unpack_parser_cls(checking_meta_directory, 0)
                unpack_parser.parse_from_offset()
                if unpack_parser.parsed_size == checking_meta_directory.size:
                    logging.debug(f'[{checking_meta_directory.md_path}]check_by_extension: parser parsed entire file')
                    checking_meta_directory.unpack_parser = unpack_parser
                    yield checking_meta_directory
                else:
                    logging.debug(f'[{checking_meta_directory.md_path}]check_by_extension: parser parsed [0:{unpack_parser.parsed_size}], leaving [{unpack_parser.parsed_size}:{checking_meta_directory.size}] ({checking_meta_directory.size - unpack_parser.parsed_size} bytes)')
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
                    extracted_md.unpack_parser = SynthesizingParser.with_size(checking_meta_directory, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
                    yield extracted_md

                    # stop after first successful extension parse
                    # TODO: make this configurable?
                    return

            except UnpackParserException as e:
                logging.debug(f'[{checking_meta_directory.md_path}]check_by_extension: parser exception: {e}')


#####
#
# Iterator that yields all combinations of offsets and UnpackParsers for a specific signature
# found in mapped_file.
#
def find_offsets_for_signature(signature, unpack_parsers, mapped_file):
    s_offset, s_text = signature
    for r in re.finditer(re.escape(s_text), mapped_file):
        logging.debug(f'find_offsets_for_signature: match for {s_text!r} at {r.start()}, offset={s_offset}, {unpack_parsers=}')
        if r.start() < s_offset:
            continue
        # TODO: prescan? or let the unpack_parser.parse() handle that?
        for u in unpack_parsers:
            yield r.start() - s_offset, u

#####
#
# Iterator that yields all combinations of offsets and UnpackParsers for all signatures
# found in mapped_file.
#
def find_signature_parsers(scan_environment, mapped_file):
    for s, unpack_parsers in scan_environment.get_unpackparsers_for_signatures().items():
        logging.debug(f'find_signature_parsers: {s} parsed by {unpack_parsers}')
        # find offsets for signature
        for offset, unpack_parser in find_offsets_for_signature(s, unpack_parsers, mapped_file):
            yield offset, unpack_parser

#####
#
# Iterator that yields succesfully parsed parts in meta_directory.mapped_file and the parts
# that are not
# parsed, in order. It chooses the first signature that it parses successfully, and will not
# yield any overlapping results. In case of the same offset, the order of the signature
# parsers as configured in the scan_environment determines the order in which it tries
# parsing with UnpackParsers. If you want a different order, change the way
# find_signature_parsers is sorted, perhaps with parser priorities.
#
def scan_signatures(scan_environment, meta_directory):
    scan_offset = 0
    for offset, unpack_parser_cls in sorted(find_signature_parsers(scan_environment, meta_directory.mapped_file), key=itemgetter(0)):
        logging.debug(f'[{meta_directory.md_path}]scan_signatures: at {scan_offset}, found parser at {offset}, {unpack_parser_cls}')
        if offset < scan_offset: # we have passed this point in the file, ignore the result
            logging.debug(f'[{meta_directory.md_path}]scan_signatures: skipping [{offset}:{scan_offset}]')
            continue
        # try if the unpackparser works
        try:
            logging.debug(f'[{meta_directory.md_path}]scan_signatures: try parse at {offset} with {unpack_parser_cls}')
            unpack_parser = unpack_parser_cls(meta_directory, offset)
            unpack_parser.parse_from_offset()
            if offset == 0 and unpack_parser.parsed_size == meta_directory.size:
                logging.debug(f'[{meta_directory.md_path}]scan_signatures: skipping [{scan_offset}:{unpack_parser.parsed_size}], covers entire file, yielding {unpack_parser} and return')
                yield 0, unpack_parser
                return
            if offset > scan_offset:
                # if it does, yield a synthesizing parser for the padding before the file
                logging.debug(f'[{meta_directory.md_path}]scan_signatures: [{scan_offset}:{offset}] yields SynthesizingParser, length {offset - scan_offset}')
                yield scan_offset, SynthesizingParser.with_size(meta_directory, offset, offset - scan_offset)
            # yield the part that the unpackparser parsed
            logging.debug(f'[{meta_directory.md_path}]scan_signatures: [{offset}:{offset+unpack_parser.parsed_size}] yields {unpack_parser}, length {unpack_parser.parsed_size}')
            yield offset, unpack_parser
            scan_offset = offset + unpack_parser.parsed_size
        except UnpackParserException as e:
            logging.debug(f'[{meta_directory.md_path}]scan_signatures: parser exception in {unpack_parser}: {e}')
    # yield the trailing part
    if 0 < scan_offset < meta_directory.size:
        logging.debug(f'[{meta_directory.md_path}]scan_signatures: [{scan_offset}:{meta_directory.size}] yields SynthesizingParser, length {meta_directory.size - scan_offset}')
        yield scan_offset, SynthesizingParser.with_size(meta_directory, offset, meta_directory.size - scan_offset)


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
        logging.debug(f'[{checking_meta_directory.md_path}]check_by_signature: got match at {offset}: {unpack_parser} length {unpack_parser.parsed_size}')
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
    for unpack_parser_cls in scan_environment.get_unpackparsers_for_featureless_files():
        logging.debug(f'[{checking_meta_directory.md_path}]check_featureless: {unpack_parser_cls}')
        try:
            unpack_parser = unpack_parser_cls(checking_meta_directory, 0)
            unpack_parser.parse_from_offset()
            if unpack_parser.parsed_size == checking_meta_directory.size:
                logging.debug(f'[{checking_meta_directory.md_path}]check_featureless: parser parsed entire file')
                checking_meta_directory.unpack_parser = unpack_parser
                yield checking_meta_directory
            else:
                logging.debug(f'[{checking_meta_directory.md_path}]check_featureless: parser parsed [0:{unpack_parser.parsed_size}], leaving [{unpack_parser.parsed_size}:{checking_meta_directory.size - unpack_parser.parsed_size} bytes')
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
                extracted_md.unpack_parser = SynthesizingParser.with_size(checking_meta_directory, unpack_parser.parsed_size, checking_meta_directory.size - unpack_parser.parsed_size)
                yield extracted_md

                # stop after first successful extension parse
                # TODO: make this configurable?
                return

        except UnpackParserException as e:
            logging.debug(f'[{checking_meta_directory.md_path}]check_featureless: parser exception: {e}')





    pass

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
def process_job(scanjob):
    # scanjob has: path, meta_directory object and context
    meta_directory = scanjob.meta_directory
    logging.debug(f'[scanjob.meta_directory.md_path]process_job: enter')

    # TODO: if we want to record meta data for unscannable files, change
    # this into an iterator pattern where you will get MetaDirectories with an
    # assigned parser to write the meta data. Be aware that we may not be able to
    # open unscannable files, so this parser must be special.
    if is_unscannable(meta_directory.file_path):
        return

    with meta_directory.open():

        # TODO: see if we can decide if files are padding from the MetaDirectory context.
        # if scanjob.context_is_padding(meta_directory.context): return
        for md in check_for_padding(meta_directory):
            with md.open(open_file=False):
                md.write_info_with_unpack_parser()
            return # skip padding file by returning

        for md in check_by_extension(scanjob.scan_environment, meta_directory):
            logging.debug(f'[scanjob.meta_directory.md_path]process_job: analyzing {md.file_path} into {md.md_path} with {md.unpack_parser}')
            for unpacked_md in md.unpack_with_unpack_parser():
                logging.debug(f'[scanjob.meta_directory.md_path]process_job: unpacked {unpacked_md.file_path}, with info in {unpacked_md.md_path}')
                job = ScanJob(unpacked_md.md_path)
                scanjob.scan_environment.scanfilequeue.put(job)
            with md.open(open_file=False):
                md.write_info_with_unpack_parser()

        # stop after first successful unpack (TODO: make configurable?)
        if meta_directory.is_scanned():
            return

        for md in check_by_signature(scanjob.scan_environment, meta_directory):
            logging.debug(f'[scanjob.meta_directory.md_path]process_job: analyzing {md.file_path} into {md.md_path} with {md.unpack_parser}')
            # if md is synthesized, queue it for extra checks?
            for unpacked_md in md.unpack_with_unpack_parser():
                job = ScanJob(unpacked_md.md_path)
                scanjob.scan_environment.scanfilequeue.put(job)
            with md.open(open_file=False):
                md.write_info_with_unpack_parser()

        # stop after first successful scan for this file (TODO: make configurable?)
        if meta_directory.is_scanned():
            return

        # if extension and signature did not give any results, try other things
        # TODO: try featureless parsers
        logging.debug(f'[scanjob.meta_directory.md_path]process_job: trying featureless parsers')

        for md in check_featureless(scanjob.scan_environment, meta_directory):
            logging.debug(f'[scanjob.meta_directory.md_path]process_job: analyzing {md.file_path} into {md.md_path} with {md.unpack_parser}')
            for unpacked_md in md.unpack_with_unpack_parser():
                job = ScanJob(unpacked_md.md_path)
                scanjob.scan_environment.scanfilequeue.put(job)
            with md.open(open_file=False):
                md.write_info_with_unpack_parser()


####
#
# Process all jobs on the scan queue in the scan_environment.
#
def process_jobs(scan_environment):
    # code smell, should not be needed if unpackparsers behave
    os.chdir(scan_environment.unpackdirectory)

    while True:
        try:
            # TODO: check if timeout long enough
            logging.debug(f'process_jobs: getting scanjob')
            #scanjob = scan_environment.scanfilequeue.get(timeout=86400)
            # we can wait forever, because we use a JoinableQueue
            scanjob = scan_environment.scanfilequeue.get()
            logging.debug(f'process_jobs: {scanjob=}')
        except queue.Empty as e:
            logging.debug(f'process_jobs: empty scan queue')
            break
        scanjob.scan_environment = scan_environment
        process_job(scanjob)
        logging.debug(f'process_jobs: scanjob done.')
        scan_environment.scanfilequeue.task_done()

    logging.debug(f'process_jobs: nothing more in queue.')
    #scan_environment.scanfilequeue.join()

