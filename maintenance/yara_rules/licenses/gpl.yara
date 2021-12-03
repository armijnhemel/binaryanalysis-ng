rule gpl: license copyleft
{
    meta:
        description = "Rule for GPL"
        name = "gpl"

    strings:

        $string1 = "gnu.org/licenses/gpl."
        $string2 = "gnu.org/copyleft/gpl."
        $string3 = "www.opensource.org/licenses/gpl-license.php"
        $string4 = "www.fsf.org/copyleft/gpl.html"
        $string5 = "general public license" nocase

    condition:
        any of ($string*)

}
