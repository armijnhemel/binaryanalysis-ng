rule mpl: license
{
    meta:
        description = "Rule for MPL license"
        name = "mpl"

    strings:

        $string1 = "mozilla.org/MPL"

    condition:
        any of ($string*)

}
