rule gpl: license
{
    meta:
        description = "Rule for GPL"
        name = "gpl"

    strings:

        // Extracted strings

        $string1 = "gnu.org/licenses/gpl."
        $string2 = "gnu.org/copyleft/gpl."
        $string3 = "www.opensource.org/licenses/gpl-license.php"
        $string4 = "www.fsf.org/copyleft/gpl.html"

    condition:
        any of ($string*)

}
