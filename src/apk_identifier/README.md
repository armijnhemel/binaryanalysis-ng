# Process APK files with APKiD

`APKiD` (<https://github.com/rednaga/APKiD>) is a tool to analyze Android
APK files and report if any obfuscation techniques were used. It describes
itself as:

```
Android Application Identifier for Packers, Protectors, Obfuscators and
Oddities - PEiD for Android 
```

## APKiD in BANG

The program in this directory is a proof of concept to see how `APKiD`
can work in conjunction with BANG. This script is expected to run repeatedly
to report on newly found obfuscation techniques for which detectors are added
regularly to `APKiD`.

## Running `apk_identifier.py`

The `apk_identifier.py` script needs two parameters:

1. a configuration file (in YAML)
2. a path to a BANG meta directory

The meta directory is typically `root` if you want to scan things for an
entire image, but this doesn't have to be: you can also scan everything
underneath a single meta directory (for example representing a single partition
of an Android device).

```
$ python3 apk_identifier.py -c apk-config.yaml -r ~/tmp/bang/root/
```

## TODO

Things that need to be figured out in a wider context (not this script):

* storing results
* retrieving earlier stored results
