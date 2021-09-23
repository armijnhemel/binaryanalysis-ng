import pickle

lq_funcs = open('low_quality_funcs', 'r').readlines()

lq_vars = open('low_quality_vars', 'r').readlines()

lq_pickle = open('low_quality_identifiers.pickle', 'wb')

pickle.dump({'functions': lq_funcs, 'variables': lq_vars}, lq_pickle)

lq_pickle.close()
