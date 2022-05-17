let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = []; };

  my-python = pkgs.python39.withPackages (p: with p; [
    deepdiff
    defusedxml
    dockerfile-parse
    elasticsearch
    icalendar
    kaitaistruct
    meilisearch
    packageurl-python
    parameterized
    pdfminer
    psycopg2
    pydot
    pytest
    pyyaml
    requests
    tinycss2
    tlsh
    yara-python
  ]);

in
pkgs.mkShell {
  buildInputs = with pkgs; [
    apkid
    binutils
    cve-bin-tool
    openjdk8
    openssl
    my-python
    qemu
    utillinux
  ];
}
