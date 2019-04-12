let
  pkgs = import <nixpkgs> {};

  my-python = pkgs.python3.withPackages (p: with p; [
    defusedxml
    dockerfile-parse
    icalendar
    lz4
    pillow
    psycopg2
    python-snappy
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
    utillinux
    zstd
  ];
}
