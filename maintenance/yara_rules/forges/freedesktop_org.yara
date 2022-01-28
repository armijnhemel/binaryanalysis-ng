rule freedesktop_org: forge
{
    meta:
        description = "Rule for Freedesktop.org SCM references"
        name = "freedesktop_org"

    strings:

        $string1 = "cvs.freedesktop.org"
        $string2 = "cgit.freedesktop.org"
        $string3 = "gitweb.freedesktop.org"
        $string4 = "gitlab.freedesktop.org"
        $string5 = "anongit.freedesktop.org"

    condition:
        any of ($string*)

}
