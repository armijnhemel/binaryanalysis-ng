rule libstemmer: license
{
    meta:
        description = "Rule for libstemmer license"
        name = "libstemmer"

    strings:

        $string1 = "snowball.tartarus.org/license.php"

    condition:
        any of ($string*)

}
