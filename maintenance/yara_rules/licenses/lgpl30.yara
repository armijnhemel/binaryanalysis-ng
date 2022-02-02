rule lgpl30: license copyleft
{
    meta:
        description = "Rule for LGPL3.0"
        name = "lgpl30"

    strings:

        $string1 = "www.gnu.org/licenses/lgpl-3.0-standalone.html"
        $string2 = "opensource.org/licenses/LGPL-3.0"
        $string3 = "opensource.org/licenses/lgpl-3.0."

    condition:
        any of ($string*)

}
