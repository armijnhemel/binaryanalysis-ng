rule debian: forge
{
    meta:
        description = "Rule for Debian SCM references"
        name = "debian"

    strings:

        $string1 = "git.debian.org"
        $string2 = "anonscm.debian.org"
        $string3 = "salsa.debian.org/"

    condition:
        any of ($string*)

}
