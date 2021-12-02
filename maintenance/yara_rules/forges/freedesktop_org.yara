rule freedesktop_org: forge
{
    meta:
        description = "Rule for Freedesktop.org SCM references"
        name = "freedesktop_org"

    strings:

        $string1 = "cvs.freedesktop.org"
        $string2 = "git.freedesktop.org"

    condition:
        any of ($string*)

}
