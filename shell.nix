let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pyahocorasickOverlay = _final: prev: {
    python3 = prev.python3.override {
      packageOverrides = _pyFinal: pyPrev: {
        pyahocorasick = pyPrev.pyahocorasick.overrideAttrs (oldAttrs: {
          preBuild = (oldAttrs.preBuild or "") + "export AHOCORASICK_BYTES=1";
        });
      };
    };
  };

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = [ pyahocorasickOverlay ]; };

  my-python = pkgs.python3.withPackages (p: with p; [
    brotli
    click
    deepdiff
    defusedxml
    dockerfile-parse
    icalendar
    kaitaistruct
    leb128
    lz4
    mutf8
    python-lzo
    parameterized
    pdfminer
    pefile
    pillow
    protobuf
    pwntools
    pyahocorasick
    pyaxmlparser
    pytest
    python-snappy
    pyyaml
    rich
    telfhash
    textual
    tlsh
    xxhash
    zstandard
  ]);
    
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    binutils
    bzip3
    cabextract
    e2fsprogs
    e2tools
    erofs-utils
    innoextract
    kaitai-struct-compiler
    lrzip
    lz4
    ncompress
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
    zchunk
  ];
}
