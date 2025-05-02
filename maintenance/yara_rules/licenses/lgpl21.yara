rule lgpl21: license copyleft
{
    meta:
        description = "Rule for LGPL2.1"
        name = "lgpl21"

    strings:

        $string1 = "gnu.org/licenses/old-licenses/lgpl-2.1"
        $string2 = "creativecommons.org/licenses/LGPL/2.1/"
        $string3 = "opensource.org/licenses/LGPL-2.1"

    condition:
        any of ($string*)

}
