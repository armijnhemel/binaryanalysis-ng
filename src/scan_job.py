import os
import re
import mmap
import logging
from operator import itemgetter
from meta_directory import *
from UnpackParser import SynthesizingParser, ExtractingParser, PaddingParser
from UnpackParserException import UnpackParserException
import bangsignatures

class ScanJob:
    def __init__(self, path):
        self._path = path
        self._meta_directory = None

    def set_scan_environment(self, scan_environment):
        self.scan_environment = scan_environment

    @property
    def meta_directory(self):
        if self._meta_directory is None:
            self._meta_directory = MetaDirectory.from_md_path(self.scan_environment.unpackdirectory, self._path)
        return self._meta_directory

def is_unscannable(path):
    # TODO: do we want labels on unscannable files?
    return not path.is_file() or path.stat().st_size == 0
    # return path.is_dir() or path.is_fifo() or path.is_socket() or path.is_block_device() or path.is_char_device() or path.is_symlink()

def is_padding(path):
    validpadding = [b'\x00', b'\xff']
    ispadding = False

    with path.open('rb') as f:
        c = f.read(1)
        padding_char = c
        ispadding = c in validpadding
        if ispadding:
            while c == padding_char:
                c = f.read(1)
            ispadding = c == b''
    return ispadding

def extract_file(checking_meta_directory, in_file, offset, file_size):
    extracted_path = checking_meta_directory.extracted_filename(offset, file_size)
    abs_extracted_path = checking_meta_directory.meta_root / extracted_path
    abs_extracted_path.parent.mkdir(parents=True, exist_ok=True)
    with abs_extracted_path.open('wb') as extracted_file:
        os.sendfile(extracted_file.fileno(), in_file.fileno(), offset, file_size)
    extracted_md = MetaDirectory(checking_meta_directory.meta_root, None, False)
    extracted_md.file_path = extracted_path
    checking_meta_directory.add_extracted_file(extracted_md)
    return extracted_md


def check_for_padding(checking_meta_directory):
    with checking_meta_directory.abs_file_path.open('rb') as in_file:
        try:
            unpack_parser = PaddingParser(in_file, 0)
            unpack_parser.parse_from_offset()
            logging.debug(f'check_for_padding: size = {unpack_parser.parsed_size}/{checking_meta_directory.size}')
            if unpack_parser.parsed_size == checking_meta_directory.size:
                logging.debug(f'check_for_padding: yield {unpack_parser} for {checking_meta_directory.file_path}')
                checking_meta_directory.unpack_parser = unpack_parser
                yield checking_meta_directory
        except UnpackParserException as e:
            logging.debug(f'check_for_padding: parser exception: {e}')

        logging.debug(f'check_for_padding: {checking_meta_directory.file_path} is not a padding file')

def find_extension_parsers(scan_environment, mapped_file):
    for ext, unpack_parsers in scan_environment.get_unpackparsers_for_extensions().items():
        for unpack_parser_cls in unpack_parsers:
            logging.debug(f'find_extension_parser: {ext!r} parsed by {unpack_parser_cls}')
            yield ext, unpack_parser_cls

def check_by_extension(scan_environment, checking_meta_directory):
    with checking_meta_directory.abs_file_path.open('rb') as in_file:
        mapped_file = mmap.mmap(in_file.fileno(),0, access=mmap.ACCESS_READ)
        for ext, unpack_parser_cls in find_extension_parsers(scan_environment, mapped_file):
            if bangsignatures.matches_file_pattern(checking_meta_directory.file_path, ext):
                logging.debug(f'check_by_extension: {unpack_parser_cls} parses extension {ext}')
                try:
                    unpack_parser = unpack_parser_cls(mapped_file, 0)
                    unpack_parser.parse_from_offset()
                    if unpack_parser.parsed_size == mapped_file.size():
                        logging.debug(f'check_by_extension: parser parsed entire file')
                        checking_meta_directory.unpack_parser = unpack_parser
                        yield checking_meta_directory
                    else:
                        logging.debug(f'check_by_extension: parser parsed [0:{unpack_parser.parsed_size}], leaving [{unpack_parser.parsed_size}:{mapped_file.size()}] ({mapped_file.size() - unpack_parser.parsed_size} bytes)')
                        # yield the checking_meta_directory with a ExtractingUnpackParser, in
                        # case we want to record metadata about it.
                        checking_meta_directory.unpack_parser = ExtractingParser.with_parts(
                            mapped_file,
                            [ (0,unpack_parser.parsed_size),
                            (unpack_parser.parsed_size, mapped_file.size() - unpack_parser.parsed_size) ]
                            )
                        yield checking_meta_directory

                        # yield the matched part of the file
                        extracted_md = extract_file(checking_meta_directory, in_file, 0, unpack_parser.parsed_size)
                        extracted_md.unpack_parser = unpack_parser
                        yield extracted_md

                        # yield a synthesized file
                        extracted_md = extract_file(checking_meta_directory, in_file, unpack_parser.parsed_size, mapped_file.size() - unpack_parser.parsed_size)
                        extracted_md.unpack_parser = SynthesizingParser.with_size(mapped_file, unpack_parser.parsed_size, mapped_file.size() - unpack_parser.parsed_size)
                        yield extracted_md

                        # stop after first successful extension parse
                        # TODO: make this configurable?
                        return

                except UnpackParserException as e:
                    logging.debug(f'check_by_extension: parser exception: {e}')


def find_offsets_for_signature(signature, unpack_parsers, mapped_file):
    s_offset, s_text = signature
    for r in re.finditer(re.escape(s_text), mapped_file):
        logging.debug(f'find_offsets_for_signature: match for {s_text!r} at {r.start()}, offset={s_offset}')
        if r.start() < s_offset:
            continue
        # TODO: prescan? or let the unpack_parser.parse() handle that?
        for u in unpack_parsers:
            yield r.start() - s_offset, u

def find_signature_parsers(scan_environment, mapped_file):
    for s, unpack_parsers in scan_environment.get_unpackparsers_for_signatures().items():
        logging.debug(f'find_signature_parsers: {s} parsed by {unpack_parsers}')
        # find offsets for signature
        for offset, unpack_parser in find_offsets_for_signature(s, unpack_parsers, mapped_file):
            yield offset, unpack_parser

def scan_signatures(scan_environment, mapped_file):
    scan_offset = 0
    for offset, unpack_parser_cls in sorted(find_signature_parsers(scan_environment, mapped_file), key=itemgetter(0)):
        logging.debug(f'scan_signatures: at {scan_offset}, found parser at {offset}, {unpack_parser_cls}')
        if offset < scan_offset: # we have passed this point in the file, ignore the result
            logging.debug(f'scan_signatures: skipping [{offset}:{scan_offset}]')
            continue
        # try if the unpackparser works
        try:
            logging.debug(f'scan_signatures: try parse at {offset} with {unpack_parser_cls}')
            unpack_parser = unpack_parser_cls(mapped_file, offset)
            unpack_parser.parse_from_offset()
            if offset == 0 and unpack_parser.parsed_size == mapped_file.size():
                logging.debug(f'scan_signatures: skipping [{scan_offset}:{unpack_parser.parsed_size}], covers entire file, yielding {unpack_parser} and return')
                yield 0, unpack_parser
                return
            if offset > scan_offset:
                # if it does, yield a synthesizing parser for the padding before the file
                logging.debug(f'scan_signatures: [{scan_offset}:{offset}] yields SynthesizingParser, length {offset - scan_offset}')
                yield scan_offset, SynthesizingParser.with_size(mapped_file, offset, offset - scan_offset)
            # yield the part that the unpackparser parsed
            logging.debug(f'scan_signatures: [{offset}:{offset+unpack_parser.parsed_size}] yields {unpack_parser}, length {unpack_parser.parsed_size}')
            yield offset, unpack_parser
            scan_offset = offset + unpack_parser.parsed_size
        except UnpackParserException as e:
            logging.debug(f'scan_signatures: parser exception: {e}')
    # yield the trailing part
    if 0 < scan_offset < mapped_file.size():
        logging.debug(f'scan_signatures: [{scan_offset}:{mapped_file.size()}] yields SynthesizingParser, length {mapped_file.size() - scan_offset}')
        yield scan_offset, SynthesizingParser.with_size(mapped_file, offset, mapped_file.size() - scan_offset)


def check_by_signature(scan_environment, checking_meta_directory):
    # find offsets
    with checking_meta_directory.abs_file_path.open('rb') as in_file:
        mapped_file = mmap.mmap(in_file.fileno(),0, access=mmap.ACCESS_READ)
        parts = [] # record the parts for the ExtractingParser
        for offset, unpack_parser in scan_signatures(scan_environment, mapped_file):
            logging.debug(f'check_by_signature: got match at {offset}: {unpack_parser} length {unpack_parser.parsed_size}')
            if offset == 0 and unpack_parser.parsed_size == checking_meta_directory.size:
                # no need to extract a subfile
                checking_meta_directory.unpack_parser = unpack_parser
                yield checking_meta_directory
            else:
                extracted_md = extract_file(checking_meta_directory, in_file, offset, unpack_parser.parsed_size)
                extracted_md.unpack_parser = unpack_parser
                yield extracted_md
                parts.append((offset, unpack_parser.parsed_size))
            # yield ExtractingParser
            if parts != []:
                checking_meta_directory.unpack_parser = ExtractingParser.with_parts(mapped_file, parts)
                yield checking_meta_directory

def process_job(scanjob):
    # scanjob has: path, meta_directory object and context
    meta_directory = scanjob.meta_directory

    if is_unscannable(meta_directory.file_path):
        return

    # if scanjob.context_is_padding(meta_directory.context): return
    for md in check_for_padding(meta_directory):
        logging.debug(f'process padding file in {md} with {md.unpack_parser}')
        md.unpack_parser.write_info(md)
        return # skip padding file by returning

    for md in check_by_extension(scanjob.scan_environment, meta_directory):
        logging.debug(f'process_job: analyzing {md.file_path} into {md.md_path} with {md.unpack_parser}')
        # md is an meta_directory
        # unpackdirectory has files to unpack (i.e. for archives)
        for unpacked_md in md.unpack_parser.unpack(md):
            logging.debug(f'process_job: unpacked {unpacked_md.file_path}, with info in {unpacked_md.md_path}')
            # queue up
            pass
        md.unpack_parser.write_info(md)

    # stop after first successful unpack (TODO: make configurable?)
    if meta_directory.is_scanned():
        return

    for md in check_by_signature(scanjob.scan_environment, meta_directory):
        logging.debug(f'process_job: analyzing {md.file_path} into {md.md_path} with {md.unpack_parser}')
        # if md is synthesized, queue it for extra checks?
        for unpacked_md in md.unpack_parser.unpack(md):
            # queue
            pass
        md.unpack_parser.write_info(md)

    # stop after first successful scan for this file (TODO: make configurable?)
    if meta_directory.is_scanned():
        return

    # if extension and signature did not give any results, try other things
    # TODO: try featureless parsers

def process_jobs(scan_environment):
    # code smell, should not be needed if unpackparsers behave
    os.chdir(scan_environment.unpackdirectory)

    while True:
        try:
            # TODO: check if timeout long enough
            scanjob = scan_environment.scanfilequeue.get(timeout=86400)
        except scan_environment.scanfilequeue.Empty as e:
            break
        scanjob.set_scan_environment(scan_environment)
        process_job(scanjob)
        scan_environment.scanfilequeue.task_done()


