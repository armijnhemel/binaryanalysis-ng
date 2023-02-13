# Processing BANG file results

An important task after unpacking files is to process the results. The way that
the results are stored can sometimes be a challenge: it is not a clear
directory hierarchy and results are stored, with metadata, in separate
directories that are placed next to each other. This has benefits and
drawbacks: the benefit is that a whole directory (example: an unpacked squashfs
file system) can be processed, without recursive unpacking results
interfering. The drawback is that traversing the full data structure is a
little bit of work.

## Walking the BANG result data structure

The BANG result directory consists of directories containing data and
metadata. The root directory is always called `root`. If there are any results
that are unpacked, then the data will be stored in a subdirectories with the
following name, depending on what data was unpacked:

1. `rel` - data stored with a relative path (example: various
   file systems, archives)
2. `abs` - data stored with an absolute path
3. `extracted` - carved data

Some example code to process code (lifted from `src/cve/cve_finder.py` and
adapted, see the original file for the full version):

```
# open the top level pickle
bang_pickle = result_directory / 'info.pkl'

# load the pickle
bang_data = pickle.load(open(bang_pickle, 'rb'))

# create a deque to store results in and retrieve results from
file_deque = collections.deque()
file_deque.append(bang_pickle)

# walk the unpack tree recursively
while True:
    try:
        orig_file_pickle = file_deque.popleft()
    except:
        break

    try:
        bang_data = pickle.load(open(orig_file_pickle, 'rb'))
    except:
        continue

    # add the unpacked/extracted files to the deque
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
```

This particular code focuses on just reading the pickles and traversing the
data structure. In other programs some other actions could be taken (see for
example `src/vis/visualise_bang.py` for code that creates graphviz output).
