let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = []; };

  my-python = pkgs.python39.withPackages (p: with p; [
    click
    defusedxml
    lz4
    psycopg2
    pytest
    pyyaml
    requests
  ]);
    
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    my-python
  ];
}
