let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config = {}; overlays = []; };

  my-python = pkgs.python3.withPackages (p: with p; [
    deepdiff
    defusedxml
    dockerfile-parse
    elasticsearch
    icalendar
    kaitaistruct
    lz4
    parameterized
    pefile
    pillow
    psycopg2
    pytest
    python-snappy
    pyyaml
    requests
    tinycss2
    tlsh
  ]);
    
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    binutils
    cabextract
    e2tools
    libxml2
    lz4
    lzop
    mailcap
    ncompress
    openjdk8
    openssl
    my-python
    qemu
    rzip
    sbt
    squashfsTools
    unshield
    utillinux
    zstd
  ];
}
