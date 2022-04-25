rule mpl10: license
{
    meta:
        description = "Rule for MPL 1.0 license"
        name = "mpl10"

    strings:

        $string1 = "opensource.org/licenses/MPL-1.0"
        $string2 = "opensource.org/licenses/mozilla1.0.php"

    condition:
        any of ($string*)

}
