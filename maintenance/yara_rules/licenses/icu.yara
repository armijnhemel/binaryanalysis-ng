rule icu: license
{
    meta:
        description = "Rule for ICU license"
        name = "icu"

    strings:

        $string1 = "source.icu-project.org/repos/icu/icu/trunk/license.html"
        $string2 = "source.icu-project.org/repos/icu/trunk/icu4c/LICENSE"

    condition:
        any of ($string*)

}
