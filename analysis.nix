let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = []; };

  my-python = pkgs.python39.withPackages (p: with p; [
    cve-bin-tool
    deepdiff
    defusedxml
    dockerfile-parse
    elasticsearch
    icalendar
    kaitaistruct
    parameterized
    pdfminer
    psycopg2
    pytest
    pyyaml
    tinycss2
    tlsh
  ]);
    
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    binutils
    libxml2
    openjdk8
    openssl
    my-python
    qemu
    utillinux
  ];
}
