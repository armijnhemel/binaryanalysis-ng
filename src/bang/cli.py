import multiprocessing
import click
import pathlib
import logging
import time
import pprint
from .ScanEnvironment import *
from .scan_job import ScanJob, process_jobs
from .meta_directory import MetaDirectory
from . import bangsignatures
from .log import log

BANG_VERSION = "0.0.1"

def create_scan_environment_from_config(config):
    e = ScanEnvironment(
            # set the maximum size for the amount of bytes to be read
            maxbytes = 0,
            # set the size of bytes to be read during scanning hashes
            readsize = 10240,
            createbytecounter = False,
            createjson = False,
            tlshmaximum = False,
            synthesizedminimum = 10,
            paddingname = 'PADDING',
            unpackdirectory = '',
            temporarydirectory = '',
            resultsdirectory = '',
            scan_queue = None,
            resultqueue = None,
            processlock = None,
            checksumdict = None,
            )
    return e


@click.group()
def app():
    pass


# bang scan <input file>
@app.command()
@click.option('-c', '--config')
@click.option('-v', '--verbose', is_flag=True)
@click.option('-u', '--unpack-directory', type=click.Path(path_type=pathlib.Path), default=pathlib.Path('/tmp'))
@click.option('-t', '--temporary-directory', type=click.Path(path_type=pathlib.Path), default=pathlib.Path('/tmp'))
@click.option('-j', '--jobs', default=1, type=int)
@click.argument('path', type=click.Path())
def scan(config, verbose, unpack_directory, temporary_directory, jobs, path):
    # set up the environment
    scan_environment = create_scan_environment_from_config(config)
    scan_environment.temporarydirectory = temporary_directory.absolute()
    scan_environment.unpackdirectory = unpack_directory.absolute()

    if verbose:
        log.setLevel(logging.DEBUG)

    log.info(f'cli:scan: BANG version {BANG_VERSION}')
    log.info(f'cli:scan: start [{time.time_ns()}]')

    # set the unpack_parsers
    # TODO: use config to enable/disable parsers
    #log.debug(f' finding unpack_parsers ')
    unpack_parsers = bangsignatures.get_unpackers()
    scan_environment.set_unpackparsers(unpack_parsers)
    #log.debug(f'{unpack_parsers =}')
    scan_environment.build_automaton()

    # set up the jobs
    process_manager = multiprocessing.Manager()
    scan_queue = process_manager.JoinableQueue(maxsize=0)
    scan_environment.scan_semaphore = process_manager.Semaphore(jobs)
    scan_environment.scan_queue = scan_queue

    processes = [ multiprocessing.Process(target = process_jobs, args = (scan_environment,)) for i in range(jobs)]


    # queue the file
    md = MetaDirectory(scan_environment.unpackdirectory, None, True)
    md.file_path = pathlib.Path(path).absolute()
    log.debug(f'cli:scan[{md.md_path}]: queued job [{time.time_ns()}]')
    j = ScanJob(md.md_path)
    scan_queue.put(j)

    # start processes
    log.debug(f'cli:scan: starting processes...')
    for p in processes: p.start()

    log.debug(f'cli:scan: waiting for all processes to finish...')
    scan_queue.join()
    log.debug(f'cli:scan: all processes in queue finished')

    log.debug(f'cli:scan: terminating processes...')
    for p in processes:
        p.terminate()
    log.debug(f'cli:scan: done.')


@app.command()
@click.option('-a', '--all', is_flag=True)
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
def show(all, metadir):
    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    print(f'{md.md_path} ({md.file_path}):')
    with md.open(open_file=False):
        print(f'Labels: {", ".join(md.info.get("labels",[]))}')
        print(f'Metadata:')
        pprint.pprint(md.info.get('metadata'))
        if all:
            for k,v in md.info.get('extracted_files', {}).items():
                print(f'{k}\t{v}')
            for k,v in md.info.get('unpacked_absolute_files', {}).items():
                print(f'{k}\t{v}')
            for k,v in md.info.get('unpacked_relative_files', {}).items():
                print(f'{k}\t{v}')


@app.command()
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
def ls(metadir):
    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    with md.open(open_file=False):
        for k,v in md.info.get('extracted_files', {}).items():
            print(f'{k}\t{v}')
        for k,v in md.info.get('unpacked_absolute_files', {}).items():
            print(f'{k}\t{v}')
        for k,v in md.info.get('unpacked_relative_files', {}).items():
            print(f'{k}\t{v}')



if __name__=="__main__":
    app()

