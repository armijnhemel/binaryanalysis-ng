#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes BANG results and generates JSON output that can
later be used to generate YARA files for dynamically linked ELF files
and Android Dex files.
'''

import collections
import datetime
import json
import multiprocessing
import os
import pathlib
import pickle
import re
import sys

import click

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from yara_config import YaraConfig, YaraConfigException

# YARA escape sequences
ESCAPE = str.maketrans({'"': '\\"',
                        '\\': '\\\\',
                        '\t': '\\t',
                        '\n': '\\n'})

NAME_ESCAPE = str.maketrans({'.': '_',
                             '-': '_'})


def process_bang(yara_queue, yara_directory, yara_binary_directory,
                      process_lock, processed_files, yara_env):
    '''Generate a YARA file for a single ELF or Dex binary'''

    generate_identifier_files = yara_env['generate_identifier_files']
    while True:
        bang_pickle = yara_queue.get()

        # open the pickle
        bang_data = pickle.load(open(bang_pickle, 'rb'))

        # store the type of executable
        if 'elf' in bang_data['labels']:
            exec_type = 'elf'
        else:
            exec_type = 'dex'

        # there is a bug where sometimes no hashes are computed
        if 'hashes' not in bang_data['metadata']:
            yara_queue.task_done()
            continue

        path_name = bang_pickle.with_name('pathname')
        with open(path_name, 'r') as path_name_file:
             file_name = pathlib.Path(path_name_file.read()).name

        # TODO: filter empty files
        sha256 = bang_data['metadata']['hashes']['sha256']

        process_lock.acquire()

        # try to catch duplicates
        if sha256 in processed_files:
            process_lock.release()
            yara_queue.task_done()
            continue

        processed_files[sha256] = ''
        process_lock.release()

        # set metadata
        metadata = {'sha256': sha256, 'name': file_name}

        if 'tlsh' in bang_data['metadata']['hashes']:
            metadata['tlsh'] = bang_data['metadata']['hashes']['tlsh']

        strings = []

        if exec_type == 'elf':
            elf_info = {}
            symbols = []

            if 'telfhash' in bang_data['metadata']:
                metadata['telfhash'] = bang_data['metadata']['telfhash']

            # process strings
            if 'strings' in bang_data['metadata']:
                for s in bang_data['metadata']['strings']:
                    # ignore whitespace-only strings
                    if re.match(r'^\s+$', s) is None:
                        strings.append(s.translate(ESCAPE))

            # process symbols, split in functions and variables
            if bang_data['metadata']['symbols'] != []:
                for s in bang_data['metadata']['symbols']:
                    if s['section_index'] == 0:
                        continue
                    if yara_env['ignore_weak_symbols']:
                        if s['binding'] == 'weak':
                            continue
                    if '@@' in s['name']:
                        identifier_name = s['name'].rsplit('@@', 1)[0]
                    elif '@' in s['name']:
                        identifier_name = s['name'].rsplit('@', 1)[0]
                    else:
                        identifier_name = s['name']
                    symbols.append(s)

            # dump JSON
            elf_info['metadata'] = metadata
            elf_info['strings'] = strings
            elf_info['symbols'] = symbols
            elf_info['tags'] = yara_env['tags'] + ['elf']
            json_file = yara_binary_directory / ("%s-%s.json" % (metadata['name'], metadata['sha256']))
            with open(json_file, 'w') as json_dump:
                json.dump(elf_info, json_dump, indent=4)
        elif exec_type == 'dex':
            dex_classes = []

            for c in bang_data['metadata']['classes']:
                # filter useless data
                methods = []
                fields = []
                for method in c['methods']:
                    # ignore whitespace-only methods
                    if re.match(r'^\s+$', method['name']) is not None:
                        continue
                    if method['name'] in ['<init>', '<clinit>']:
                        continue
                    if method['name'].startswith('access$'):
                        continue
                    methods.append(method)

                for field in c['fields']:
                    # ignore whitespace-only methods
                    if re.match(r'^\s+$', field['name']) is not None:
                        continue

                if methods != [] or fields != []:
                    class_info = {}
                    if 'source' in c:
                        class_info['source'] = c['source']
                    if 'classname' in c:
                        class_info['classname'] = c['classname']
                    class_info['methods'] = methods
                    class_info['fields'] = fields
                    dex_classes.append(class_info)

            # dump JSON
            dex_info = {}
            dex_info['tags'] = yara_env['tags'] + ['dex']
            dex_info['classes'] = dex_classes
            dex_info['metadata'] = metadata
            json_file = yara_binary_directory / ("%s-%s.json" % (metadata['name'], metadata['sha256']))
            with open(json_file, 'w') as json_dump:
                json.dump(dex_info, json_dump, indent=4)

        yara_queue.task_done()


@click.command(short_help='process BANG result files and output YARA')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', help='BANG result directories', type=click.Path(exists=True), required=True)
@click.option('--identifiers', '-i', help='pickle with low quality identifiers', type=click.File('rb'))
def main(config_file, result_directory, identifiers):

    # store the result directory as a pathlib Path instead of str
    result_directory = pathlib.Path(result_directory)

    # result_directory should be a real directory
    if not result_directory.is_dir():
        print("Error: %s is not a directory, exiting." % result_directory, file=sys.stderr)
        sys.exit(1)

    # parse the configuration
    yara_config = YaraConfig(config_file)
    yara_env = yara_config.parse()

    yara_binary_directory = yara_env['yara_directory'] / 'binary'

    yara_binary_directory.mkdir(exist_ok=True)

    processmanager = multiprocessing.Manager()

    # ignore object files (regular and GHC specific)
    ignored_elf_suffixes = ['.o', '.p_o']

    # create a lock to control access to any shared data structures
    process_lock = multiprocessing.Lock()

    # create a shared dictionary
    processed_files = processmanager.dict()

    # create a queue for scanning files
    yara_queue = processmanager.JoinableQueue(maxsize=0)
    processes = []

    # read the root pickle
    try:
        bang_pickle = result_directory / 'info.pkl'
        if not bang_pickle.exists():
            print(f"Error: cannot find {bang_pickle}, exiting.", file=sys.stderr)
            sys.exit(1)
    except PermissionError:
        print(f"Error: cannot read {bang_pickle} (permission error?), exiting.", file=sys.stderr)
        sys.exit(1)

    # create a deque to store results in and retrieve results from
    file_deque = collections.deque()
    file_deque.append(bang_pickle)

    # walk the unpack tree recursively
    while True:
        try:
            bang_pickle = file_deque.popleft()
        except:
            break

        try:
            bang_data = pickle.load(open(bang_pickle, 'rb'))
        except:
            continue

        path_name = bang_pickle.with_name('pathname')
        with open(path_name, 'r') as path_name_file:
             root_name = pathlib.Path(path_name_file.read()).name

        if 'labels' in bang_data:
            if 'ocaml' in bang_data['labels']:
                if yara_env['ignore_ocaml']:
                    continue
            if 'elf' in bang_data['labels']:
                suffix = pathlib.Path(root_name).suffix

                if suffix in ignored_elf_suffixes:
                    continue

                if 'static' in bang_data['labels']:
                    if not 'linuxkernelmodule' in bang_data['labels']:
                        # TODO: clean up for linux kernel modules
                        continue

                yara_queue.put(bang_pickle)
            elif 'dex' in bang_data['labels']:
                yara_queue.put(bang_pickle)

        # add the unpacked/extracted files to the deque
        if 'unpacked_relative_files' in bang_data:
            for unpacked_file in bang_data['unpacked_relative_files']:
                file_meta_directory = bang_data['unpacked_relative_files'][unpacked_file]
                file_pickle = result_directory.parent / file_meta_directory / 'info.pkl'
                file_deque.append(file_pickle)
        if 'unpacked_absolute_files' in bang_data:
            for unpacked_file in bang_data['unpacked_absolute_files']:
                file_meta_directory = bang_data['unpacked_absolute_files'][unpacked_file]
                file_pickle = result_directory.parent / file_meta_directory / 'info.pkl'
                file_deque.append(file_pickle)
        if 'extracted_files' in bang_data:
            for unpacked_file in bang_data['extracted_files']:
                file_meta_directory = bang_data['extracted_files'][unpacked_file]
                file_pickle = result_directory.parent / file_meta_directory / 'info.pkl'
                file_deque.append(file_pickle)

    # tags = ['debian', 'debian11']
    tags = []

    generate_identifier_files = False

    # expand yara_env with binary scanning specific values
    yara_env['tags'] = tags
    yara_env['generate_identifier_files'] = generate_identifier_files

    # create processes for unpacking archives
    for i in range(0, yara_env['threads']):
        process = multiprocessing.Process(target=process_bang,
                                          args=(yara_queue, yara_env['yara_directory'],
                                                yara_binary_directory, process_lock,
                                                processed_files, yara_env))
        processes.append(process)

    # start all the processes
    for process in processes:
        process.start()

    yara_queue.join()

    # Done processing, terminate processes
    for process in processes:
        process.terminate()


if __name__ == "__main__":
    main()
