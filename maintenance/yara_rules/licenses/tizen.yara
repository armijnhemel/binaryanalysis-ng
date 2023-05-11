rule tizen: license
{
    meta:
        description = "Rule for Tizen license"
        name = "tizen"

    strings:

        $string1 = "www.tizenopensource.org/license"

    condition:
        any of ($string*)

}
