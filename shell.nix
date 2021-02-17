let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config = {}; overlays = []; };

  my-python = pkgs.python3.withPackages (p: with p; [
    defusedxml
    dockerfile-parse
    elasticsearch
    icalendar
    kaitaistruct
    lz4
    pillow
    psycopg2
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
    squashfsTools
    unshield
    utillinux
    zstd
  ];
}
