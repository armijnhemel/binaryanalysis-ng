#!/usr/bin/env python3

'''
This script reads two files with names of low quality functions and variable
names (one per line) and turns them into a pickle which can be used by scripts
to ignore low quality identifiers.
'''

import pickle

lq_elf_funcs = list(map(lambda x: x.strip(), open('low_quality_elf_funcs', 'r').readlines()))

lq_elf_vars = list(map(lambda x: x.strip(), open('low_quality_elf_vars', 'r').readlines()))

lq_elf_strings = list(map(lambda x: x.strip(), open('low_quality_elf_strings', 'r').readlines()))

lq_dex_funcs = []

lq_dex_vars = []

lq_dex_strings = []

lq_pickle = open('low_quality_identifiers.pickle', 'wb')

pickle.dump({'elf': {'functions': lq_elf_funcs, 'variables': lq_elf_vars, 'strings': lq_elf_strings},
             'dex': {'functions': lq_dex_funcs, 'variables': lq_dex_vars, 'strings': lq_dex_strings}},
            lq_pickle)

lq_pickle.close()
