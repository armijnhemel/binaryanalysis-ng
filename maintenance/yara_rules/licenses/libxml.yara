rule libxml: license
{
    meta:
        description = "Rule for libxml license"
        name = "libxml"

    strings:

        $string1 = "xmlsoft.org/FAQ.html#License"

    condition:
        any of ($string*)

}
