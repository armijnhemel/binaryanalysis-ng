rule lgpl: license
{
    meta:
        description = "Rule for LGPL"
        name = "lgpl"

    strings:

        // Extracted strings

        $string1 = "www.fsf.org/copyleft/lesser.html"
        $string2 = "www.fsf.org/licenses/lgpl.html"
        $string3 = "gnu.org/licenses/lgpl.html"
        $string4 = "opensource.org/licenses/lgpl-license"

    condition:
        any of ($string*)

}
