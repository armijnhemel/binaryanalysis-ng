# Using the F-Droid crawler

The F-Droid crawler can be used to download software as packaged by the
F-Droid project.

# Prerequisites

The script requires Python 3 and the `requests` module (external module).

# Configuration

The script uses a configuration file in YAML format. The various options are
documented in the example configuration file. Copy the example configuration
file and adapt accordingly.

It is possible to set the location of a mirror of F-Droid to download from
as well as indicate whether source, binaries or both should be downloaded.

Although the crawler performs various sanity checks it is advised to always
check that the information in the configuration file as well as the downloaded
data is correct.

# Running the script

To automatically download from a Debian mirror adapt the configuration file and
run:

    $ python3 fdroidcrawl.py -c crawler.config

This will download the F-Droid XML file from the F-Droid mirror, parse it and
download all packages that are mentioned in the configuration file.

# Acknowledgement

This project has received funding from the European Union’s Horizon 2020
research and innovation programme within the framework of the NGI-POINTER
Project funded under grant agreement No. 871528.
