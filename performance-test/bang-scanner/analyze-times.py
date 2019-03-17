#!/usr/bin/python3

import sys
import pickle
import pathlib
import csv


def get_execution_info(scandir):
    # get bang.pickle in scandir
    scanresult = pickle.load(open(pathlib.Path(scandir) / 'bang.pickle', 'rb'))
    duration = scanresult['session']['duration']
    checkfile = scanresult['session'].get('checkfile', 'unknown')
    return (scandir, checkfile, duration)

if __name__ == "__main__":
    headers = [('scandir','checkfile','duration')]
    r = [get_execution_info(arg) for arg in sys.argv[1:]]
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerows(headers + r)
