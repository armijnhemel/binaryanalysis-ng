# Remarks about ELF identifiers processed from Debian 11

There are low quality strings that are not useful to include. Some
observations:

* several binary packages are made from a single source code package like gcc
and related. While the identifiers occur in many different *binaries* they
come from the same packages. What would be needed is to map these to a single
package first.
* strings from frameworks, interpreters, etc. are often shared. Think Boost,
OCaml, and so on.

Examples:

* `unix_lbasename` - GCC & binutils related
* `htab_elements` - GCC & binutils related


* `caml_apply4` - OCaml related
* `unix_getsockopt_aux` & friends - OCaml related
