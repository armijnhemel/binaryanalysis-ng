rule apache20: license
{
    meta:
        description = "Rule for Apache 2.0"
        name = "apache20"

    strings:

        $string1 = "apache.org/licenses/LICENSE-2.0"
        $string2 = "opensource.org/licenses/apache2.0.php"

    condition:
        any of ($string*)

}
