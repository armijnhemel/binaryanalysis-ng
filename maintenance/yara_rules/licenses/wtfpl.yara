rule wtfpl: license
{
    meta:
        description = "Rule for WTFPL license"
        name = "wtfpl"

    strings:

        $string1 = "sam.zoy.org/wtfpl/"

    condition:
        any of ($string*)

}
