let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = []; };

  my-python = pkgs.python3.withPackages (p: with p; [
    brotli
    deepdiff
    defusedxml
    kaitaistruct
    leb128
    lz4
    python-lzo
    parameterized
    pdfminer
    pefile
    pillow
    protobuf
    pytest
    python-snappy
    pyyaml
    telfhash
    tlsh
  ]);
    
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    binutils
    cabextract
    e2tools
    innoextract
    libxml2
    lz4
    mailcap
    ncompress
    openjdk8
    openssl
    my-python
    protobuf
    qemu
    rzip
    sasquatch
    squashfsTools
    unrar
    unshield
    utillinux
    zstd
  ];
}
