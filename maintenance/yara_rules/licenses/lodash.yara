rule lodash: license
{
    meta:
        description = "Rule for lodash license"
        name = "lodash"

    strings:

        $string1 = "lodash.com/license"

    condition:
        any of ($string*)

}
