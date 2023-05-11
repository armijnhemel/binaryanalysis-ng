rule lgpl20: license copyleft
{
    meta:
        description = "Rule for LGPL2.0"
        name = "lgpl20"

    strings:

        $string1 = "gnu.org/licenses/old-licenses/lgpl-2.0"

    condition:
        any of ($string*)

}
