#!/usr/bin/env python3

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

import datetime
import logging
import multiprocessing
import pathlib
import sys
import tarfile
import time

from collections import deque

import click
import rich
import rich.console
import rich.markdown
import rich.pretty
import rich.table
import rich.tree

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from .scan_environment import *
from .scan_job import ScanJob, process_jobs, make_scan_pipeline
from .meta_directory import MetaDirectory, MetaDirectoryException
from . import parser_utils
from .log import log

BANG_VERSION = "0.0.1"

def create_scan_environment_from_config(config=None):
    e = ScanEnvironment(
            unpack_directory = '',
            scan_queue = None,
            )
    return e


@click.group()
def app():
    pass


# bang scan_directory <input directory>
@click.option('-c', '--config', 'config_file', type=click.File('r'))
@click.option('-v', '--verbose', is_flag=True, help='Enable debug logging')
@click.option('-u', '--unpack-directory', type=click.Path(path_type=pathlib.Path),
              default=pathlib.Path('/tmp'), help='Directory to unpack to')
@click.option('-t', '--temporary-directory', type=click.Path(path_type=pathlib.Path, exists=True),
              default=pathlib.Path('/tmp'), help='Temporary directory')
@click.option('-i', '--ignore-list', type=click.File('r'))
@click.option('-j', '--jobs', default=1, type=click.IntRange(min=1),
              help='Number of jobs running simultaneously')
@click.option('--job-wait-time', default=1, type=int, help='Time to wait for a new job')
@click.option('-f', '--force', is_flag=True,
              help='Ignore warnings about existing unpacking directory')
@click.argument('path', type=click.Path(path_type=pathlib.Path, exists=True))
@app.command(short_help='Scan a directory of files')
@click.pass_context
def scan_directory(ctx, config_file, verbose, unpack_directory, temporary_directory,
                   ignore_list, jobs, job_wait_time, force, path):
    '''Scans files in PATH and unpacks its files to a sudirectory of UNPACK_DIRECTORY.
    '''
    if config_file is not None:
        # read the configuration file. This is in YAML format
        try:
            config = load(config_file, Loader=Loader)
        except (YAMLError, PermissionError, UnicodeDecodeError):
            print("Cannot open configuration file, exiting", file=sys.stderr)
            sys.exit(1)

    for scan_archive in sorted(path.glob('**/*')):
        # first create a directory similar as the file name
        scan_dir = unpack_directory / (scan_archive.name)
        try:
            scan_dir.mkdir(parents=True)
        except FileExistsError:
            continue

        ctx.invoke(scan, config_file=config_file, verbose=verbose, unpack_directory=scan_dir,
                   temporary_directory=temporary_directory, ignore_list=ignore_list, jobs=jobs,
                   job_wait_time=job_wait_time, force=force, path=scan_archive)


# bang scan <input file>
@app.command(short_help='Scan a file')
@click.option('-c', '--config', 'config_file', type=click.File('r'))
@click.option('-v', '--verbose', is_flag=True, help='Enable debug logging')
@click.option('-u', '--unpack-directory', type=click.Path(path_type=pathlib.Path),
              default=pathlib.Path('/tmp'), help='Directory to unpack to')
@click.option('-t', '--temporary-directory', type=click.Path(path_type=pathlib.Path, exists=True),
              default=pathlib.Path('/tmp'), help='Temporary directory')
@click.option('-i', '--ignore-list', type=click.File('r'))
@click.option('-j', '--jobs', default=1, type=click.IntRange(min=1),
              help='Number of jobs running simultaneously')
@click.option('--job-wait-time', default=1, type=int, help='Time to wait for a new job')
@click.option('-f', '--force', is_flag=True,
              help='Ignore warnings about existing unpacking directory')
@click.argument('path', type=click.Path(path_type=pathlib.Path, exists=True))
def scan(config_file, verbose, unpack_directory, temporary_directory, ignore_list,
         jobs, job_wait_time, force, path):
    '''Scans PATH and unpacks its files to UNPACK_DIRECTORY.
    '''

    # record the starting time of the scan
    start_time = datetime.datetime.now(datetime.UTC)
    ignore_parsers = []
    config = None

    if unpack_directory.exists() and not force:
        print("Unpacking directory already exists, exiting", file=sys.stderr)
        sys.exit(1)

    if config_file is not None:
        # read the configuration file. This is in YAML format
        try:
            config = load(config_file, Loader=Loader)
        except (YAMLError, PermissionError, UnicodeDecodeError):
            print("Cannot open configuration file, exiting", file=sys.stderr)
            sys.exit(1)
        if 'parsers' in config:
            if config['parsers'] is not None:
                ignore_parsers = config['parsers'].get('ignore', [])

    ignore = set()

    if ignore_list is not None:
        # read the ignore list file. This is in YAML format
        try:
            ignore_dicts = load(ignore_list, Loader=Loader)
            ignore.update(k['sha256'] for k in ignore_dicts)
        except (YAMLError, PermissionError, UnicodeDecodeError):
            print("Cannot open ignore list file, exiting", file=sys.stderr)
            sys.exit(1)

    # TODO: make configurable
    #tlsh_ignore = set()
    tlsh_ignore = set(['compressed', 'encrypted', 'graphics', 'audio', 'archive',
            'filesystem', 'srec', 'ihex', 'padding', 'database', 'ignored', 'utmp',
            'resource', 'rpm', 'stone', 'vim swap', 'pcap', 'pcapng', 'edid'])

    # set up the environment
    scan_environment = create_scan_environment_from_config(config)
    scan_environment.job_wait_time = job_wait_time
    scan_environment.configuration.temporary_directory = temporary_directory.absolute()
    scan_environment.unpack_directory = unpack_directory.absolute()
    scan_environment.ignore = ignore
    scan_environment.tlsh_ignore = tlsh_ignore

    if verbose:
        log.setLevel(logging.DEBUG)

    log.info(f'cli:scan: BANG version {BANG_VERSION}')
    log.info(f'cli:scan: start [{time.time_ns()}]')

    # set the unpack_parsers
    # TODO: use config to enable/disable parsers
    #log.debug(f' finding unpack_parsers ')
    unpack_parsers = parser_utils.get_unpackers()

    if ignore_parsers != []:
        scan_environment.parsers.unpackparsers = list(filter(lambda x: x.pretty_name not in ignore_parsers, unpack_parsers))
    else:
        scan_environment.parsers.unpackparsers = unpack_parsers

    #log.debug(f'{unpack_parsers =}')
    scan_environment.parsers.build_automaton()
    scan_environment.signature_chunk_size = max(scan_environment.signature_chunk_size, scan_environment.parsers.max_chunk_size)

    # set up the process manager and initialize the barrier
    # with the value of the amount of jobs: this is the maximum
    # amount of jobs that will be able to run concurrently.
    process_manager = multiprocessing.Manager()
    scan_environment.barrier = process_manager.Barrier(jobs)

    # create a queue
    scan_queue = process_manager.Queue(maxsize=0)
    scan_environment.scan_queue = scan_queue

    # create a scan pipeline for parsing and unpacking files
    scan_pipeline = make_scan_pipeline()

    # create $jobs processes
    processes = [ multiprocessing.Process(target = process_jobs, args = (scan_pipeline, scan_environment,)) for i in range(jobs)]

    # first create a meta directory for the file
    md = MetaDirectory(scan_environment.unpack_directory, None, True)
    md.file_path = path.absolute()
    log.debug(f'cli:scan[{md.md_path}]: queued job [{time.time_ns()}]')

    # create a scanjob using the created meta directory
    j = ScanJob(md.md_path)

    # queue the scanjob
    scan_queue.put(j)

    # start processes
    log.debug('cli:scan: starting processes...')
    for p in processes: p.start()

    log.debug('cli:scan: waiting for all processes to finish...')
    for p in processes: p.join()
    log.debug('cli:scan: all processes in queue finished')

    log.debug('cli:scan: terminating processes...')
    for p in processes:
        p.terminate()
    log.debug('cli:scan: done.')

    stop_time = datetime.datetime.now(datetime.UTC)


@app.command(short_help='Show bang scan results')
@click.option('-a', '--all', 'show_all', is_flag=True,
              help='Show all information, including extracted/unpacked files')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
@click.option('--pretty', is_flag=True, help='pretty print')
def show(show_all, metadir, pretty):
    '''Shows bang scan results stored in METADIR.
    '''

    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    try:
        #print(f'{md.md_path} ({md.file_path}):')
        m = f'{md.file_path}'
    except MetaDirectoryException:
        print(f'directory {metadir} not found, exiting', file=sys.stderr)
        sys.exit(1)

    console = rich.console.Console()

    meta_table = build_meta_table(md)
    console.print(meta_table)

    if show_all:
        reporters = parser_utils.get_reporters()
        labels = md.info.get("labels", [])
        for r in reporters:
            for l in labels:
                if l in r.tags:
                    reporter = r()
                    title, report_results = reporter.create_report(md)
                    #console.print(title)
                    for res in report_results:
                        console.print(res)

        # print any unpacked files
        table, link_table, have_unpack_results, have_link_results = build_unpack_link_tables(md, metadir.parent, pretty)
        if have_unpack_results:
            console.print(table)
        if have_link_results:
            console.print(link_table)

def build_meta_table(md):
    '''Construct a parser meta information table given a meta directory'''
    with md.open(open_file=False, info_write=False):
        meta_table = rich.table.Table('', '', title='Parser data', show_lines=True,
                                      show_header=False)
        meta_table.add_row('Meta directory', f'{md.md_path}')
        meta_table.add_row('Original file', f'{md.file_path}')
        meta_table.add_row('Parser', f'{md.info.get("unpack_parser")}')
        meta_table.add_row('Labels', f'{", ".join(md.info.get("labels",[]))}')
        if md.info.get('size') is not None:
            meta_table.add_row('Parsed size', f'{md.info.get("size")}')
        if md.info.get("metadata", []) != []:
            metadata = md.info.get("metadata", [])
            if 'hashes' in metadata:
                for h in metadata['hashes']:
                    meta_table.add_row(h, f'{metadata["hashes"][h]}')

    return meta_table

def build_unpack_link_tables(md, parent, pretty=False):
    with md.open(open_file=False, info_write=False):
        table = rich.table.Table(title='Unpacked', row_styles=['dim', ''])
        table.add_column('Nr', justify='right')
        table.add_column('Name')
        table.add_column('Labels')
        table.add_column('Meta directory')

        link_table = rich.table.Table(title='Linked', row_styles=['dim', ''])
        link_table.add_column('Nr', justify='right')
        link_table.add_column('Link name')
        link_table.add_column('Link target')
        link_table.add_column('Link type')

        have_unpack_results = False
        have_link_results = False

        counter = 1
        for k,v in sorted(md.info.get('extracted_files', {}).items()):
            have_unpack_results = True
            child_md = MetaDirectory.from_md_path(parent, v)

            if pretty:
                pp_path = pathlib.Path('').joinpath(*list(k.parts[2:]))
            else:
                pp_path = k

            with child_md.open(open_file=False, info_write=False):
                labels = ", ".join(child_md.info.get("labels", []))
                table.add_row(str(counter), str(pp_path), labels, str(v))
            counter += 1

        for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
            have_unpack_results = True
            child_md = MetaDirectory.from_md_path(parent, v)

            if pretty:
                pp_path = pathlib.Path('/').joinpath(*list(k.parts[2:]))
            else:
                pp_path = k

            with child_md.open(open_file=False, info_write=False):
                labels = ", ".join(child_md.info.get("labels", []))
                table.add_row(str(counter), str(pp_path), labels, str(v))
            counter += 1

        for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
            have_unpack_results = True
            child_md = MetaDirectory.from_md_path(parent, v)

            if pretty:
                pp_path = pathlib.Path('/').joinpath(*list(k.parts[2:]))
            else:
                pp_path = k

            with child_md.open(open_file=False, info_write=False):
                labels = ", ".join(child_md.info.get("labels", []))
                table.add_row(str(counter), str(pp_path), labels, str(v))
            counter += 1

        counter = 1
        for k,v in sorted(md.info.get('unpacked_symlinks', {}).items()):
            have_link_results = True

            if pretty:
                pp_path = pathlib.Path('/').joinpath(*list(k.parts[2:]))
            else:
                pp_path = k

            link_table.add_row(str(counter), str(pp_path), str(v), 'symbolic link')
            counter += 1
        for k,v in sorted(md.info.get('unpacked_hardlinks', {}).items()):
            have_link_results = True

            if pretty:
                pp_path = pathlib.Path('/').joinpath(*list(k.parts[2:]))
            else:
                pp_path = k

            link_table.add_row(str(counter), str(pp_path), str(v), 'hardlink')
            counter += 1
    return table, link_table, have_unpack_results, have_link_results

@app.command(short_help='Pretty print full scan tree')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
@click.option('--pretty', is_flag=True, help='pretty print path names (without metadirectory)')
def print_tree(metadir, pretty):
    '''Shows bang scan results stored in METADIR as a tree
    '''
    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    try:
        m = f'{md.file_path}'
    except MetaDirectoryException:
        print(f'directory {metadir} not found, exiting', file=sys.stderr)
        sys.exit(1)

    # recursively build subtrees
    with md.open(open_file=False, info_write=False):
        pp, tree, have_children = build_tree(md, metadir.parent, pretty=pretty)
        rich.print(tree)

def build_tree(md, parent, labels='', pretty=False, cut_leading_slash=False):
    '''Build a subtree for pretty printing'''

    if pretty:
        if not md.file_path.is_absolute():
            if cut_leading_slash:
                pp_path = pathlib.Path('').joinpath(*list(md.file_path.parts[2:]))
            else:
                pp_path = pathlib.Path('/').joinpath(*list(md.file_path.parts[2:]))
        else:
            pp_path = md.file_path.name
    else:
        pp_path = md.file_path

    if labels == '':
        tree = rich.tree.Tree(f'{pp_path}')
    else:
        #tree = rich.tree.Tree(f'{pp_path}     [bold]{labels}[/bold]')
        tree = rich.tree.Tree(f'{pp_path}')

    subtrees = []

    for k,v in sorted(md.info.get('extracted_files', {}).items()):
        child_md = MetaDirectory.from_md_path(parent, v)
        with child_md.open(open_file=False, info_write=False):
            labels = ", ".join(child_md.info.get("labels", []))
            subtree = build_tree(child_md, parent, labels, pretty=pretty, cut_leading_slash=True)
            subtrees.append(subtree)

    for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
        child_md = MetaDirectory.from_md_path(parent, v)
        with child_md.open(open_file=False, info_write=False):
            labels = ", ".join(child_md.info.get("labels", []))
            subtree = build_tree(child_md, parent, labels, pretty=pretty, cut_leading_slash=False)
            subtrees.append(subtree)

    for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
        child_md = MetaDirectory.from_md_path(parent, v)
        with child_md.open(open_file=False, info_write=False):
            labels = ", ".join(child_md.info.get("labels", []))
            subtree = build_tree(child_md, parent, labels, pretty=pretty, cut_leading_slash=False)
            subtrees.append(subtree)

    for k,v in sorted(md.info.get('unpacked_symlinks', {}).items()):
        if pretty:
            link_pp_path = pathlib.Path('/').joinpath(*list(k.parts[2:]))
        else:
            link_pp_path = k
        #link_label = f'{link_pp_path}  \u2192  {v}'
        link_label = f'{link_pp_path}  \U0001f87a  {v}'
        subtrees.append((link_pp_path, link_label, True))
    for k,v in sorted(md.info.get('unpacked_hardlinks', {}).items()):
        if pretty:
            link_pp_path = pathlib.Path('/').joinpath(*list(k.parts[2:]))
        else:
            link_pp_path = k
        #link_label = f'{link_pp_path}  \u2192  {v}'
        link_label = f'{link_pp_path}  \U0001f87a  {v}'
        subtrees.append((link_pp_path, link_label, True))

    for subtree, t, have_children in sorted(subtrees):
        tree.add(t)

    have_children = False
    if subtrees:
        have_children = True
    return (pp_path, tree, have_children)

@app.command(short_help='Lists extracted and unpacked files')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
@click.option('--pretty', is_flag=True, help='pretty print')
def ls(metadir, pretty):
    '''Lists extracted and unpacked files stored in METADIR.
    '''
    console = rich.console.Console()

    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    table, link_table, have_unpack_results, have_link_results = build_unpack_link_tables(md, metadir.parent, pretty)

    if have_unpack_results:
        console.print(table)
    if have_link_results:
        console.print(link_table)

@app.command(short_help='Report BANG results (extensive) for a single metadir')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
@click.option('--pretty', is_flag=True, help='pretty print')
def report(metadir, pretty):
    console = rich.console.Console()

    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    try:
        m = f'{md.file_path}'
    except MetaDirectoryException:
        print(f'directory {metadir} not found, exiting', file=sys.stderr)
        sys.exit(1)

    # header first
    mark = rich.markdown.Markdown(f'# REPORT FOR {md.file_path}')
    console.print(mark)

    # extract the information for the root file
    with md.open(open_file=False, info_write=False):

        # print the tree (if any)
        pp, tree, have_children = build_tree(md, metadir.parent, labels='', pretty=pretty)
        if have_children:
            mark = rich.markdown.Markdown(f'## Unpacking tree for {md.file_path}')
            console.print(mark)
            console.print(tree)

    mark = rich.markdown.Markdown('---')
    console.print(mark)
    mark = rich.markdown.Markdown(f'## Files found in {md.file_path}')
    console.print(mark)
    console.line()
    report_for_file(md, metadir.parent, console, pretty)

def report_for_file(md, parent, console, pretty=False):
    # header first
    mark = rich.markdown.Markdown(f'### FILE: {md.file_path}')
    console.print(mark)

    # print the parser meta information
    meta_table = build_meta_table(md)
    console.print(meta_table)

    table, link_table, have_unpack_results, have_link_results = build_unpack_link_tables(md, parent, pretty)

    # print individual tables
    if have_unpack_results:
        console.print(table)
    if have_link_results:
        console.print(link_table)

    mark = rich.markdown.Markdown('---')
    console.print(mark)
    console.line()

    # then recurse into all of the children and pretty print
    with md.open(open_file=False, info_write=False):
        for k,v in sorted(md.info.get('extracted_files', {}).items()):
            child_md = MetaDirectory.from_md_path(parent, v)
            report_for_file(child_md, parent, console, pretty)

        for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
            child_md = MetaDirectory.from_md_path(parent, v)
            report_for_file(child_md, parent, console, pretty)

        for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
            child_md = MetaDirectory.from_md_path(parent, v)
            report_for_file(child_md, parent, console, pretty)

@app.command(short_help='Pack results in a gzip compressed tar archive')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
@click.option('-o', '--output', type=click.Path(path_type=pathlib.Path),
              required=True, help='output archive')
@click.option('--with-data', is_flag=True, help='include data in archive')
def pack(metadir, with_data, output):
    '''Stores results of upacked files stored underneath metadir
    '''
    # sanity check: is this a valid BANG unpacking directory?
    root_pickle = metadir / 'info.pkl'
    if not root_pickle.exists():
        print("Not a valid BANG directory, info.pkl not found, exiting",
              file=sys.stderr)
        sys.exit(1)

    # first grab all of the directories that need to be processed.
    # This is done by traversing the unpacking tree for a few reasons:
    #
    # 1. it allows subtrees to be packed
    # 2. unpacking trees might have been polluted by reusing the
    #    same directory for unpacking
    unpack_directories = [pathlib.Path(metadir.name)]
    root_md = MetaDirectory.from_md_path(metadir.parent, metadir.name)

    metadirs = deque([root_md])

    while True:
        try:
            md = metadirs.popleft()
        except IndexError:
            break

        # recurse into all of the children
        with md.open(open_file=False, info_write=False):
            for k,v in sorted(md.info.get('extracted_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                metadirs.append(child_md)
                unpack_directories.append(v)

            for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                metadirs.append(child_md)
                unpack_directories.append(v)

            for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                metadirs.append(child_md)
                unpack_directories.append(v)

    # then try to open the tarfile in write mode
    with tarfile.open(output, mode='w:gz') as pack_file:
        for u in unpack_directories:
            if with_data:
                pack_file.add(metadir.parent / u, arcname=u, filter=clear_ids)
            else:
                pack_file.add(metadir.parent / u / 'info.pkl', arcname=u / 'info.pkl', filter=clear_ids)
                pack_file.add(metadir.parent / u / 'pathname', arcname=u / 'pathname', filter=clear_ids)

        if with_data and metadir.name == 'root':
            try:
                root_file_name = metadir / 'pathname'
                with open(root_file_name, 'r') as r:
                    root_file = pathlib.Path(r.read())
                if root_file.exists():
                    pack_file.add(root_file, arcname=root_file.name, filter=clear_ids)
            except:
                pass

def clear_ids(tarinfo):
    '''Rewrite the UID and GIDs to something neutral.
       From Python's tarfile help page
    '''
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = "root"
    tarinfo.gname = "root"
    return tarinfo

@app.command(short_help='Create a directory structure as used in old BANG to easier navigate results using standard Linux shell tools')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
@click.option('-o', '--output', type=click.Path(path_type=pathlib.Path),
              required=True, help='output directory')
@click.option('-c', '--copy', 'do_copy', is_flag=True, help='Copy results instead of link')
def create_directory_view(metadir, output, do_copy):
    '''Create a directory structure as used in old BANG to easier
       navigate results using standard Linux shell tools.
    '''
    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)

    try:
        m = f'{md.file_path}'
    except MetaDirectoryException:
        print(f'directory {metadir} not found, exiting', file=sys.stderr)
        sys.exit(1)

    # first create the output directory, if it doesn't exist yet
    try:
        output.mkdir(parents=True)
    except FileExistsError:
        pass

    # first grab all of the directories that need to be processed
    # by traversing the unpacking tree.
    root_md = MetaDirectory.from_md_path(metadir.parent, metadir.name)

    metadirs = deque([root_md])

    while True:
        try:
            md = metadirs.popleft()
        except IndexError:
            break

        # recurse into all of the children
        with md.open(open_file=False, info_write=False):
            for k,v in sorted(md.info.get('extracted_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                metadirs.append(child_md)

            for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                metadirs.append(child_md)

            for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                metadirs.append(child_md)

if __name__=="__main__":
    app()
