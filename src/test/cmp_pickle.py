#!/usr/bin/env python3
#
# cmp_pickle.py file1.pickle file2.pickle
#

from deepdiff import DeepDiff
from pprint import pprint
import pickle
import sys

with open(sys.argv[1], "rb") as f:
    p1 = pickle.load(f)
with open(sys.argv[2], "rb") as f:
    p2 = pickle.load(f)


# ddiff = DeepDiff(p1, p2, verbose_level=1, view='tree')
ddiff = DeepDiff(p1.get('scantree'), p2.get('scantree'))

pprint(ddiff)
