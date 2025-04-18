#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only

'''
This script processes BANG results and generates JSON output that can
later be used to generate YARA files for dynamically linked ELF files
and Android Dex files.
'''

import collections
import json
import multiprocessing
import pathlib
import pickle
import queue
import re
import sys

import click


def process_bang(scan_queue, output_directory, process_lock, processed_files, tags):
    '''Generate a JSON output file for a single ELF or Dex binary'''

    while True:
        try:
            bang_pickle = scan_queue.get()
        except queue.Empty:
            break

        # open the pickle
        with open(bang_pickle, 'rb') as pickled_data:
            bang_data = pickle.load(pickled_data)

        # store the type of executable
        if 'elf' in bang_data['labels']:
            exec_type = 'elf'
        elif 'dex' in bang_data['labels']:
            exec_type = 'dex'
        elif 'java class' in bang_data['labels']:
            exec_type = 'java class'
        else:
            scan_queue.task_done()
            continue

        # there is a bug where sometimes no hashes are computed
        if 'hashes' not in bang_data['metadata']:
            scan_queue.task_done()
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
            scan_queue.task_done()
            continue

        processed_files[sha256] = ''
        process_lock.release()

        # set metadata
        metadata = {'sha256': sha256, 'name': file_name}

        if 'tlsh' in bang_data['metadata']['hashes']:
            metadata['tlsh'] = bang_data['metadata']['hashes']['tlsh']

        meta_info = {}
        meta_info['labels'] = []

        if exec_type == 'elf':
            strings = []
            symbols = []

            if 'telfhash' in bang_data['metadata']:
                metadata['telfhash'] = bang_data['metadata']['telfhash']

            # process strings
            if 'strings' in bang_data['metadata']:
                for s in bang_data['metadata']['strings']:
                    # ignore whitespace-only strings
                    if re.match(r'^\s+$', s) is None:
                        strings.append(s)

            # process symbols
            if bang_data['metadata'].get('symbols', []) != []:
                for s in bang_data['metadata']['symbols']:
                    if s['section_index'] == 0:
                        continue
                    symbols.append(s)

            meta_info['strings'] = strings
            meta_info['symbols'] = symbols
            if 'static' in bang_data['metadata']['elf_type']:
                if 'Linux kernel module' not in bang_data['metadata']['elf_type']:
                    meta_info['labels'].append('static')
            meta_info['tags'] = sorted(set(tags + ['elf']))
        elif exec_type == 'dex':
            meta_info['classes'] = []

            # process data for each class found in the Dex file
            for c in bang_data['metadata']['classes']:
                # store methods and fields, with associated data
                # such as strings (stored with methods)
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

                    # TODO: ignore empty strings and whitespace only strings
                    methods.append(method)

                for field in c['fields']:
                    # ignore whitespace-only fields
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
                    meta_info['classes'].append(class_info)

            meta_info['tags'] = sorted(set(tags + ['dex']))
        elif exec_type == 'java class':
            strings = []

            # process strings
            if 'strings' in bang_data['metadata']:
                for s in bang_data['metadata']['strings']:
                    # ignore whitespace-only strings
                    if re.match(r'^\s+$', s) is None:
                        strings.append(s)

            # process data for each method found in the Java class file
            for method in bang_data['metadata']['methods']:
                if method in ['<init>', '<clinit>']:
                    continue
                if method.startswith('access$'):
                    continue

            for field in bang_data['metadata']['fields']:
                # ignore whitespace-only fields
                if re.match(r'^\s+$', field) is not None:
                    continue
                if field in ['this$0']:
                    continue

        meta_info['labels'] += bang_data['labels']
        meta_info['metadata'] = metadata

        # dump JSON
        json_file = output_directory / (f"{metadata['name']}-{metadata['sha256']}.json")
        with open(json_file, 'w') as json_dump:
            json.dump(meta_info, json_dump, indent=4)

        scan_queue.task_done()


@click.command(short_help='process BANG result files and output JSON')
@click.option('--result-directory', '-r', help='BANG result directories',
              type=click.Path(exists=True), required=True)
@click.option('--output-directory', '-o', help='JSON output directory',
              type=click.Path(exists=True, path_type=pathlib.Path), required=True)
@click.option('-j', '--jobs', default=1, type=click.IntRange(min=1),
              help='Number of jobs running simultaneously')
@click.argument('tags', nargs=-1, type=str)
def main(result_directory, output_directory, jobs, tags):

    # store the result directory as a pathlib Path instead of str
    result_directory = pathlib.Path(result_directory)

    # result_directory should be a real directory
    if not result_directory.is_dir():
        print(f"Error: {result_directory} is not a directory, exiting.", file=sys.stderr)
        sys.exit(1)

    if not output_directory.is_dir():
        print(f"Error: {output_directory} is not a directory, exiting.", file=sys.stderr)
        sys.exit(1)

    processmanager = multiprocessing.Manager()

    # create a lock to control access to any shared data structures
    process_lock = multiprocessing.Lock()

    # create a shared dictionary
    processed_files = processmanager.dict()

    # create a queue for scanning files
    scan_queue = processmanager.JoinableQueue(maxsize=0)

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
        except IndexError:
            break

        try:
            bang_data = pickle.load(open(bang_pickle, 'rb'))
        except:
            continue

        # add interesting files to the scan queue
        labels = bang_data.get('labels', [])
        if 'elf' in labels:
            scan_queue.put(bang_pickle)
        elif 'dex' in labels:
            scan_queue.put(bang_pickle)
        #elif 'java class' in labels:
        #    scan_queue.put(bang_pickle)

        # add any unpacked/extracted files to the deque
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

    # create processes for unpacking archives
    processes = [ multiprocessing.Process(target=process_bang, args=(scan_queue,
                                                output_directory, process_lock,
                                                processed_files, list(tags))) for i in range(jobs)]

    # start all the processes
    for process in processes:
        process.start()

    scan_queue.join()

    # Done processing, terminate processes
    for process in processes:
        process.terminate()


if __name__ == "__main__":
    main()
