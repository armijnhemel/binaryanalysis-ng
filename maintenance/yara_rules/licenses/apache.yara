rule apache: license
{
    meta:
        description = "Rule for Apache"
        name = "apache"

    strings:

        $string1 = "apache.org/licenses/"

    condition:
        any of ($string*)

}
