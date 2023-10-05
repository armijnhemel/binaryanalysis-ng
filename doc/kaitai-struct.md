# Defining parsers with Kaitai Struct

## Introduction

Kaitai Struct is "a declarative language used to describe various binary data
structures, laid out in files or in memory".

<https://github.com/kaitai-io/kaitai_struct>
<http://kaitai.io/>

Basically it is a language to describe binary formats using a description file,
which can then be used to generate parsers for various languages.

## Installing the Kaitai Struct compiler

The easiest way to install the Kaitai Struct compiler if you are not using Nix
is to download a released zip file, as explained by the web site
<http://kaitai.io/#download> (select your prefered installation format, such as
`.deb` or `.zip`). If you do this make sure to download version 0.10 or later as
some of the grammars depend on features introduced in version 0.10.

Alternatively, you can build the compiler from scratch. This requires Scala and
the Scala build tool (`sbt`). Note that you may need a recent version of `sbt`
and download it from the `sbt` repository. You can find instructions for that
on <https://www.scala-sbt.org/download.html>.

Also note that the versions of the kaitai Python run-time and the compiler must
match, you may also need to reinstall the Python runtime.

### Building the Kaitai Struct compiler

First, you will need to checkout the repository from github if you have not done
this already:

```
git clone --recursive https://github.com/kaitai-io/kaitai_struct.git
```

See <http://doc.kaitai.io/developers.html> for more details. In my case, I
cloned the repository directly under my home directory in `~/kaitai_struct`.

During the build, the Scala build tool caches information in `~/.sbt`. If you
try to build Kaitai Struct compiler again with another version of sbt or scala,
you may run into problems. By removing the `~/.sbt` directory and rebuilding,
I managed to build the program.

After installing `sbt`, move to the compiler repository and run `sbt`:

```
cd ~/kaitai_struct/compiler
sbt compilerJVM/universal:packageBin
```

In case the version of `sbt` is different from the declared version in
`project/build.properties` you might want to change the version in
`project/build.properties` (for example: 1.4.3 vs 1.4.7).

If the build succeeds, you can find a zip archive of the Kaitai Struct compiler
in `jvm/target/universal/`. In my case, this is
`jvm/target/universal/kaitai-struct-compiler-0.9-SNAPSHOT.zip`.

Unpack the zip file somewhere and add the `bin` subdirectory to your path, or
use absolute paths to invoke the compiler.

## Installing the kaitai Python runtime

You can install the kaitai Python runtime via `pip` (be sure that this is
Python 3, since BANG uses Python 3):

```
pip install kaitaistruct
```

Make sure that the kaitai Python runtime version matches the kaitai compiler.

Alternatively, you can install it from the git repository (again, make sure
the compiler and runtime versions match):

```
cd ~/kaitai_struct/runtime/python
python3 setup.py install --user
```

The `--user` will install the module into your home directory instead of
system-wide.

## Compiling a parser

After installation of the compiler and runtime, you can use the compiler to
generate python code from a kaitai format description. For example, for a
format description for a GIF file in the file `gif.ksy`, the following
command generates a Python module `gif.py`:

```
kaitai-struct-compiler -t python gif.ksy 
```

## Debugging kaitai parsers

### Using the WebIDE

Install the web IDE according to the instructions on
<https://github.com/kaitai-io/kaitai_struct_webide>, for example:

```
git clone https://github.com/kaitai-io/ide-kaitai-io.github.io
cd ide-kaitai-io.github.io
python3 -m http.server
```

* Point your browser to <http://localhost:8000/>
* click the upload icon on the bottom left area (a cloud with an upwards arrow)
* upload a test file
* select the kaitai parser from the list
* check if the parser handles the file correctly

### Using the kaitai-struct-visualizer tools

The visualizer has two tools, `ksv`, an interactive visualizer, and `ksdump`,
a non-interactive command line visualizer. Both call `kaitai-struct-compiler`,
therefore the compiler must be in your shell's search path.

You can install the visualizer as a Ruby gem:

```
gem install kaitai-struct-visualizer
```

Note that the version of the Ruby runtime of the visualizer must match the
compiler version, which may not be the case.

You can also run the Ruby script directly from the `kaitai_struct` repository,
e.g.  `~/kaitai_struct/visualizer/bin/ksv`. If you want you can put it into
your search path just as you need to do for `kaitai-struct-compiler`.

See <https://github.com/kaitai-io/kaitai_struct_visualizer> for more details.

Run the visualizer as follows:

```
ksdump <binary-file> <ksy file>
```

or

```
ksv <binary-file> <ksy file>
```

## Issues with kaitai parsers

### Instances are lazily evaluated

Kaitai parsers can contain so called instances. These are only evaluated when
the data is accessed. That means that any size calculations or parse errors
should also take instances into account.

### Position in the stream after reading

Not all kaitai parsers read the complete file. The unpacker determines the
file length by checking how many bytes have been read from the input stream.
You must compensate for this in the unpacker that wraps the kaitai parser.
For example, the `ico` parser does not parse the contained image data. You
can either adjust `self.unpacked_size` by adding the length of the unparsed
part, call a subparser on the image data, or perhaps even both.

### Kaitai parser expects an end of stream

Kaitai parsers that expect an end of stream, for example by using `size-eos`,
or calling `size` on a kaitai stream object, cannot be used while extracting
data from a file. When extracting, we have a stream that can contain data
beyond the file that we want to extract, and therefore, our parser cannot
depend on that.

### Difficulties using `_io.size`

The BANG parsers use `OffsetInputFile`, a thin wrapper around a regular file
that hides the offset, so it appears that the file is always opened at
offset 0. This makes writing parsers easier, but the Kaitai Struct parsers
do not use `OffsetInputFile`, but the underlying file. This means that certain
things in Kaitai Struct files will not necessarily make sense, such as
using `_io.size` in the main structure of the file (the so called "stream").
The `_io.size` variable will point to the length of the *original* file, not
the wrapped file.

This has consequences example when carving files or when doing sanity checks
(it is no issue for files where parsing starts at `0` or when `_io.size` is
used in a substream). An example is the `git_index` format, for which the
following is defined in the `.ksy` file:

```
seq:
  - id: header
    type: header
  - id: entries
    type: entry
    repeat: expr
    repeat-expr: header.num_entries
  - id: extensions
    type: extension
    repeat: until
    repeat-until: _io.pos >= _io.size - len_hash
  - id: checksum
    size: len_hash
```

The `repeat-until` for the `extensions` element is depending on `_io.size`
to determine when to break out of the loop. If parsing of the file does not
start at `0`, then the wrong data is read and parsing will fail.

The solution is of course to not rely on `_io.size` in the "main" stream of
a file but sometimes this isn't always possible.

Because of this some files will not be correctly carved and unpacked if there
is extra data prepended in front of the file. As most files that are parsed
start at offset `0` this is inconvenient, but not a major problem.

Currently the following parsers are potentially affected because `_io.size`
is used in the "main" stream.

1. `au`
2. `cpio_old_binary`
3. `git_index`
4. `gpt_partition_table`
5. `quicktime`

### Handling parse errors

The UnpackParser class asks us to raise `UnpackParserExceptions` for non-fatal
errors. This means that we need to catch all parse errors when processing a
file with Kaitai Struct. You must not only handle any exceptions from calling
`from_io`, but also from any Kaitai Struct instances, as they may trigger the
kaitai parser to read data. One hack is to actually read all the instances
data inside a `try` block during parsing.

### Importing kaitai types

If you import a Kaitai Struct file in another (relative import), say
`vfat_directory_rec` the translated Python code contains:

```
import vfat_directory_rec
```

If we run tests with unittest's `discover` command, Python cannot find this
module:

```
ModuleNotFoundError: No module named 'vfat_directory_rec'
```

The compilation of the Kaitai Struct parser in the `Makefile` contains an
extra step to rewrite this import to:

```
import vfat_directory_rec
```
