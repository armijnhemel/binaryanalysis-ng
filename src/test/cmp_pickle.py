#!/usr/bin/env python3
#
# cmp_pickle.py file1.pickle file2.pickle
#

import pickle
import sys
import re

from deepdiff import DeepDiff

def report(ddiff):
    for k,v in ddiff.items():
        print('#',k)
        if re.match(r'.*_added', k):
            for x in v:
                print('+', x)
        elif re.match(r'.*_removed', k):
            for x in v:
                print('-', x)
        elif re.match(r'.*_changed', k):
            for kk, vv in v.items():
                print('*', kk)
                for kkk, vvv in vv.items():
                    if re.match(r'new_', kkk):
                        print('  +', vvv)
                    else:
                        print('  -', vvv)
        else:
            print('?', k,v)

with open(sys.argv[1], "rb") as f:
    p1 = pickle.load(f)
with open(sys.argv[2], "rb") as f:
    p2 = pickle.load(f)

def setify_labels(data):
    if isinstance(data, dict):
        for k,v in data.items():
            data[k] = setify_labels(v)
        if 'labels' in data:
            data['labels'] = set(data['labels'])
    return data

p1 = setify_labels(p1)
p2 = setify_labels(p2)

ddiff = DeepDiff(p1.get('scantree'), p2.get('scantree'))

report(ddiff)
