rule fontawesome: license
{
    meta:
        description = "Rule for font awesome license"
        name = "fontawesome"

    strings:

        $string1 = "fontawesome.io/license"

    condition:
        any of ($string*)

}
