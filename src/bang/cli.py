import multiprocessing
import click
import pathlib
import logging
from .ScanEnvironment import *
from .scan_job import ScanJob, process_jobs
from .meta_directory import MetaDirectory
from . import bangsignatures

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
            logging = False,
            paddingname = 'PADDING',
            unpackdirectory = '',
            temporarydirectory = '',
            resultsdirectory = '',
            scanfilequeue = None,
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
        logging.basicConfig(level=logging.DEBUG)


    # set the unpack_parsers
    # TODO: use config to enable/disable parsers
    logging.debug(f' finding unpack_parsers ')
    unpack_parsers = bangsignatures.get_unpackers()
    scan_environment.set_unpackparsers(unpack_parsers)
    logging.debug(f'{unpack_parsers =}')

    # set up the jobs
    process_manager = multiprocessing.Manager()
    scan_queue = process_manager.JoinableQueue(maxsize=0)
    scan_environment.scanfilequeue = scan_queue
    processes = [ multiprocessing.Process(target = process_jobs, args = (scan_environment,)) ]
    logging.debug(f'cli: starting processes...')
    for p in processes: p.start()

    # queue the file
    md = MetaDirectory(scan_environment.unpackdirectory, None, True)
    md.file_path = pathlib.Path(path).absolute()
    j = ScanJob(md.md_path)
    scan_queue.put(j)

    logging.debug(f'cli: waiting for all processes to finish...')
    scan_queue.join()
    logging.debug(f'cli: all processes in queue finished')

    logging.debug(f'cli: terminating processes...')
    for p in processes:
        p.terminate()
    logging.debug(f'cli: done.')

if __name__=="__main__":
    app()

