let
  # Use `niv update` to update nixpkgs.
  # See https://github.com/nmattia/niv/
  sources = import ./nix/sources.nix;

  pkgs = import sources.nixpkgs { config.allowUnfree = true; overlays = []; };

  my-python = pkgs.python3.withPackages (p: with p; [
    beautifulsoup4
    scrapy
    selenium
  ]);
    
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    geckodriver
    my-python
  ];
}
