rule espeak: license
{
    meta:
        description = "Rule for espeak license"
        name = "espeak"

    strings:

        $string1 = "espeak.sf.net/license.html"

    condition:
        any of ($string*)

}
