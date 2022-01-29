rule gfdl13: license
{
    meta:
        description = "Rule for GNU Free Documentation License 1.3"
        name = "gfdl13"

    strings:

        $string1 = "gnu.org/licenses/fdl-1.3.html"

    condition:
        any of ($string*)

}
