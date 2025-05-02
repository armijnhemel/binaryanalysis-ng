rule jquery: license
{
    meta:
        description = "Rule for jquery license"
        name = "jquery"

    strings:

        $string1 = "jquery.org/license"

    condition:
        any of ($string*)

}
