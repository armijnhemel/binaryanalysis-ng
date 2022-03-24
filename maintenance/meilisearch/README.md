# Meilisearch scripts

This directory contains scripts to populate a Meilisearch[1] database.
Meilisearch is an open source search engine with (some) typo tolerance.

Currently there are the following scripts:

1. Debian package information - process Debian Packages files and store
information (package name, short description, homepage, section)
2. NixOS package information

Note: this scripts currently output JSON, but will switch to the
Meilisearch Python API in the future.


# Installing Meilisearch

If your distribution already has an installable package, use your
distribution's binary package. Otherwise you can use the instructions from
the Meilisearch website. The following instructions should work:

```
$ mkdir $HOME/meilisearch
$ cd $HOME/meilisearch
$ curl -L https://install.meilisearch.com | sh
```

Launching Meilisearch can be done as follows:

```
$ cd $HOME/meilisearch
$ ./meilisearch --no-analytics
```

In this case the parameter `--no-analytics` is provided to prevent the server
from sending telemetry to Meilisearch.

By default the server will listen on `localhost` on port `7700`. This can be
changed using the commandline parameters or a separate shells cript. Please
note: currently this launches Meilisearch in development mode. To run it in
production you will need to specify that it is a production server, which also
requires you to generate and use API keys.

The code described and used here is only to be used in development mode.
Production mode is future work.


# Extracting and loading Debian package data

Debian package data can be found in the file `Packages.gz` or `Packages.xz` on
a Debian FTP mirror inside the `dists` directory, for example
`dists/Debian11.2/main/binary-amd64/`.

The data can be extracted using the script and then loaded into Meilisearch:

```
$ python3 meilisearch_debian.py -c meilisearch-config.yaml -p /tmp/Packages  > deb.json
$ curl -X POST 'http://127.0.0.1:7700/indexes/debian/documents' -H 'Content-Type: application/json' --data-binary @deb.json
```

By surfing to the standard Meilisearch web interface (in this case:
`http://127.0.0.1:7700`) and it can be used to search for packages.

# Extracting and loading NixOS package data

First extract the NixOS packages information:

```
$ nix-env -qa --json > /tmp/nix.json
```

Then process it and upload it into Meilisearch:

```
$ python3 meilisearch_nixos.py -c meilisearch-config.yaml -p /tmp/nix.json > nix-meili.json
$ curl -X POST 'http://127.0.0.1:7700/indexes/nixos/documents' -H 'Content-Type: application/json' --data-binary @nix-meili.json
```

# References

[1] https://www.meilisearch.com/
