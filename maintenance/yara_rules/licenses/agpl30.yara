rule agpl30: license copyleft
{
    meta:
        description = "Rule for AGPL-3.0"
        name = "agpl30"

    strings:

        $string1 = "licensed under the AGPL Version 3"

    condition:
        any of ($string*)

}
