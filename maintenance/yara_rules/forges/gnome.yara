rule gnome: forge
{
    meta:
        description = "Rule for GNOME Git references"
        name = "gnome"

    strings:

        $string1 = "git.gnome.org"
        $string2 = "gitlab.gnome.org"

    condition:
        any of ($string*)

}
