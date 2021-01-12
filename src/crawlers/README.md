# Using the Debian crawler

The Debian crawler can be used to download software as packaged by the
Debian project. There are two ways the crawler can be used:

1. automatically downloading software based on the content available on the Debian mirror (and as described in the ls-lR.gz files)
2. using a list extracted from the Packages.gz file for a single Debian distribution

# Prerequisites

The script requires Python 3 and the "requests" module (external module).

# Configuration

The script uses a configuration file in Windows INI format (although this might
change in the future). The various options are documented in the example
configuration file. Copy the example configuration file and adapt accordingly.

# Automatically downloading

To automatically download from a Debian mirror adapt the configuration file and
run:

    $ python3 debiancrawler.py -c crawler.config

This will download the ls-lR.gz file from the Debian mirror, parse it and
download all packages and architectures that are mentioned in the configuration
file.

# Using a list of packages

To download just a subset of packages from a distribution download the
Packages.gz list, extract the packages you want to extract (optionally edit
or filter the list) and supply it as a parameter to the script.

Example to download the Packages.gz file:

    $ wget -c http://ftp.nluug.nl/pub/os/Linux/distr/debian/dists/stable/main/binary-amd64/Packages.gz
    $ zgrep ^Filename Packages.gz > /tmp/package-list.txt

Starting 

    $ python3 debiancrawler.py -p /tmp/packages-list.txt -c crawler.config

Please note: because the Packages.gz file does not contain file sizes the extra
check to see if a file has already been downloaded does not work and files will
be redownloaded. To prevent this adapt the packages file to filter any
previously downloaded packages.

# Acknowledgement

This project has received funding from the European Union’s Horizon 2020
research and innovation programme within the framework of the NGI-POINTER
Project funded under grant agreement No. 871528.
