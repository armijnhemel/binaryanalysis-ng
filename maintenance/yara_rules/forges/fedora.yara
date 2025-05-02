rule fedora: forge
{
    meta:
        description = "Rule for Fedora Git references"
        name = "fedora"

    strings:

        $string1 = "git.fedorahosted.org"
        $string2 = "src.fedoraproject.org/cgit/"
        $string3 = "pkgs.fedoraproject.org/cgit/"

    condition:
        any of ($string*)

}
