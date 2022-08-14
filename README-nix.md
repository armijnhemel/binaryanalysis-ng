# Managing the different BANG phases with Nix

For running BANG it is advised to use the Nix package manager[1]. For the
different phases that BANG has different environments have been defined,
with matching Nix expressions:

1. firmware unpacking phase - `shell.nix`
2. maintenance phase - `maintenance.nix`
3. analysis phase - `analysis.nix`

For each of the different phases a different environment should be initiated.
The rationale behind this is that these phases can be run on different
machines, by different users, at different times.

The goal of splitting the dependencies is to keep the environments as minimal
as possible by not installing dependencies that are not needed for a particular
task. For example: when creating a knowledgebase the Kaitai Struct compiler
is not needed, but it is needed when unpacking a firmware file.

# References

[1] <https://nixos.org/>
