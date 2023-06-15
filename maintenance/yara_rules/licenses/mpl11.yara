rule mpl11: license
{
    meta:
        description = "Rule for MPL 1.1 license"
        name = "mpl11"

    strings:

        $string1 = "mozilla.org/MPL/MPL-1.1.html"
        $string2 = "opensource.org/licenses/MPL-1.1"
        $string3 = "opensource.org/licenses/mozilla1.1.php"

    condition:
        any of ($string*)

}
