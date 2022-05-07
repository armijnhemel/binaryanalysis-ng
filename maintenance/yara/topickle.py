import pickle

lq_elf_funcs = list(map(lambda x: x.strip(), open('low_quality_elf_funcs', 'r').readlines()))

lq_elf_vars = list(map(lambda x: x.strip(), open('low_quality_elf_vars', 'r').readlines()))

lq_dex_funcs = []

lq_dex_vars = []

lq_pickle = open('low_quality_identifiers.pickle', 'wb')

pickle.dump({'elf': {'functions': lq_elf_funcs, 'variables': lq_elf_vars},
             'dex': {'functions': lq_dex_funcs, 'variables': lq_dex_vars}},
            lq_pickle)

lq_pickle.close()
