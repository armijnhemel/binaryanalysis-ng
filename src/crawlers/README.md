Example:

    $ wget -c http://ftp.nluug.nl/pub/os/Linux/distr/debian/dists/stable/main/binary-amd64/Packages.gz
    $ zgrep ^Filename Packages.gz > /tmp/package-list.txt
