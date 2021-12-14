rule apache11: license
{
    meta:
        description = "Rule for Apache 1.1"
        name = "apache11"

    strings:

        $string1 = "apache.org/licenses/LICENSE-1.1"
        $string2 = "opensource.org/licenses/Apache-1.1"

    condition:
        any of ($string*)

}
