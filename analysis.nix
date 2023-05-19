let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = []; };

  my-python = pkgs.python3.withPackages (p: with p; [
    click
    deepdiff
    defusedxml
    dockerfile-parse
    icalendar
    kaitaistruct
    packageurl-python
    parameterized
    pdfminer
    psycopg2
    pydot
    pytest
    pyyaml
    qiling
    requests
    textual
    tinycss2
    tlsh
    yara-python
  ]);

in
pkgs.mkShell {
  buildInputs = with pkgs; [
    apkid
    binutils
    openjdk8
    openssl
    my-python
    qemu
    utillinux
  ];
}
