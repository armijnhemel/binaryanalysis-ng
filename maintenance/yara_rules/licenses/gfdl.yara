rule gfdl: license
{
    meta:
        description = "Rule for GNU Free Documentation License"
        name = "gfdl"

    strings:

        $string1 = "gnu.org/copyleft/fdl.html"
        $string2 = "www.fsf.org/licensing/licenses/fdl.html"

    condition:
        any of ($string*)

}
