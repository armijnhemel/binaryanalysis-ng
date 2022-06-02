let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = []; };

  my-python = pkgs.python39.withPackages (p: with p; [
    click
    cxxfilt
    defusedxml
    meilisearch
    packageurl-python
    psycopg2
    pytest
    pyyaml
    requests
    telfhash
    tlsh
    woodblock
  ]);
    
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    cvehound
    gettext
    my-python
    universal-ctags
    yara
  ];
}
