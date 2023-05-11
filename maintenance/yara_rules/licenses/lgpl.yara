rule lgpl: license copyleft
{
    meta:
        description = "Rule for LGPL"
        name = "lgpl"

    strings:

        $string1 = "www.fsf.org/copyleft/lesser.html"
        $string2 = "www.fsf.org/licenses/lgpl.html"
        $string3 = "gnu.org/licenses/lgpl.html"
        $string4 = "opensource.org/licenses/lgpl-license"
        $string5 = "lesser general public license" nocase
        $string6 = "library general public license" nocase

    condition:
        any of ($string*)

}
