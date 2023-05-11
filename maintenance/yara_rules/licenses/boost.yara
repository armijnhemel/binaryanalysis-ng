rule boost: license
{
    meta:
        description = "Rule for Boost software license"
        name = "boost"

    strings:

        $string1 = "www.boost.org/LICENSE_1_0.txt"
        $string2 = "pocoproject.org/license.html"

    condition:
        any of ($string*)

}
