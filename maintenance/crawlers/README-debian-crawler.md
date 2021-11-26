# Using the Debian crawler

The Debian crawler can be used to download software as packaged by the
Debian project or from Debian derivatives. There are two ways the crawler
can be used:

1. automatically downloading software based on the content available on the Debian mirror (and as described in the `ls-lR.gz` files)
2. using a list extracted from the `Packages.gz` file for a single Debian distribution (CURRENTLY UNSUPPORTED)

# Prerequisites

The script requires Python 3 and the `requests` module (external module).

# Configuration

The script uses a configuration file in YAML format. The various options are
documented in the example configuration file. Copy the example configuration
file and adapt accordingly.

It is possible to configure various repositories (for example: Debian and
Ubuntu). The script will download from all the repositories that are
configured in the configuration file and that are enabled.

Although the crawler performs various sanity checks it is advised to ensure
that the information in the configuration file is accurate.

# Automatically downloading

To automatically download from one or more Debian mirrors adapt the
configuration file (for example: `debian-config.yaml`) and run:

    $ python3 debiancrawler.py download --config=debian-config.yaml

This will download the `ls-lR.gz` file from each Debian mirror, parse it and
download all packages and architectures that are mentioned in the configuration
file.

# Downloading a single distribution

To download just all binary packages from a single version of a distribution
(for example: Ubuntu Hirsute) the script can be invoked in "single distribution
download" mode. The repository that the files have to be downloaded for has
to be defined in the configuration file. All the binary architectures (`all`
is currently excluded) that need to be downloaded have to be defined in the
configuration file as well.

The extra parameter is the distribution that needs to be downloaded. This
can be any name that is in the `dists` directory of a Debian/Ubuntu mirror.

An example (for Ubuntu Hirsute):

    $ python3 debiancrawler.py download-single-version --config=debian-config.yaml --repository=ubuntu --distribution=hirsute

# Acknowledgement

This project has received funding from the European Union’s Horizon 2020
research and innovation programme within the framework of the NGI-POINTER
Project funded under grant agreement No. 871528.
