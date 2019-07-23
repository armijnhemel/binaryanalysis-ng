# Defining parsers with kaitai-struct

## Introduction

kaitai-struct is ....

https://github.com/kaitai-io/kaitai_struct
http://kaitai.io/

## Installing the kaitai-struct compiler

The easiest way to install the kaitai-struct compiler is to download a released zip file, as explained by the web site http://kaitai.io/#download (select your prefered installation format, such as `.deb` or `.zip`).

Alternatively, you can build the compiler from scratch. This requires Scala and the Scala build tool. Note that you may need a recent version of sbt and download it from the sbt repository. You can find instructions for that on https://www.scala-sbt.org/download.html.
Also note that the versions of the kaitai Python run-time's and the compiler must match, you may also need to reinstall the Python runtime.

First, you will need to checkout the repository from github if you have not done this already:

```
git clone --recursive https://github.com/kaitai-io/kaitai_struct.git
```

See http://doc.kaitai.io/developers.html for more details. In my case, I cloned the repository directly under my home directory in `~/kaitai_struct`.

During the build, the Scala build tool caches information in `~/.sbt`. If you try to build kaitai-struct-compiler again with another version of sbt or scala, you may run into problems. By removing the `~/.sbt` directory and rebuilding, I managed to build the program.

After installing sbt, move to the compiler repository and run sbt:

```
cd ~/kaitai_struct/compiler
sbt compilerJVM/universal:packageBin
```

If the build succeeds, you can find a zip archive of the kaitai-struct compiler in `jvm/target/universal/`. In my case, this is `jvm/target/universal/kaitai-struct-compiler-0.9-SNAPSHOT.zip`.

Unpack the zip file somewhere and add the `bin` subdirectory to your path, or use absolute paths to invoke the compiler.

## Installing the kaitai Python runtime

You can install the kaitai Python runtime via `pip` (be sure that this is Python 3, since bang uses Python 3):

```
pip install kaitaistruct
```

Make sure that the kaitai Python runtime version matches the kaitai compiler.

Alternatively, you can install it from the git repository (again, make sure the compiler and runtime versions match):

```
cd ~/kaitai_struct/runtime/python
python3 setup.py install --user
```

The `--user` will install the module into your home directory instead of system-wide.

## Compiling a parser

After installation of the compiler and runtime, you can use the compiler to generate python code from a kaitai format description. If I had a format description for a GIF file in the file `gif.ksy`, the following command generates a Python module `gif.py`:

```
kaitai-struct-compiler -t python gif.ksy 
```


