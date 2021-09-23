{
  description = "Binary Analysis Next Generation (BANG)";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:

    let
      supportedSystems = [ "x86_64-linux" "i686-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system);
      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      });
    in {
      devShells = forAllSystems (system:
        with nixpkgsFor.${system};

        {
          default =
            let
              my-python = pkgs.python3.withPackages (p: with p; [
                brotli
                deepdiff
                defusedxml
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
                pyaxmlparser
                pytest
                python-snappy
                pyyaml
                telfhash
                tlsh
                zstd
              ]);
            in pkgs.mkShell {
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
                zchunk
                zstd
              ];
            };

          analysis =
            let
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
                yara-python
              ]);
            in pkgs.mkShell {
              buildInputs = with pkgs; [
                apkid
                binutils
                libxml2
                openjdk8
                openssl
                my-python
                qemu
                utillinux
              ];
            };

          maintenance =
            let
              my-python = pkgs.python39.withPackages (p: with p; [
                click
                cxxfilt
                defusedxml
                packageurl-python
                psycopg2
                pytest
                python-ctags3
                pyyaml
                requests
                telfhash
                tlsh
                woodblock
              ]);
            in pkgs.mkShell {
              buildInputs = with pkgs; [
                gettext
                my-python
                universal-ctags
                yara
              ];
            };

        });

      devShell = forAllSystems (system: self.devShells.${system}.default);

    };

}
