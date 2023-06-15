rule unlicense: license
{
    meta:
        description = "Rule for Unlicense"
        name = "unlicense"

    strings:

        $string1 = "unlicense.org"

    condition:
        any of ($string*)

}
