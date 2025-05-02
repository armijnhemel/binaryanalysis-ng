rule mit: license
{
    meta:
        description = "Rule for MIT license"
        name = "mit"

    strings:

        $string1 = "opensource.org/licenses/mit-license"
        $string2 = "opensource.org/licenses/MIT"

    condition:
        any of ($string*)

}
